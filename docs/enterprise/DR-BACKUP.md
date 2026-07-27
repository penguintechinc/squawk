# Disaster Recovery & Backup

## Scope

- **Manager PostgreSQL**: Token store, tenant configuration, DNS zones, DHCP pools, NTP settings
- **Valkey**: Ephemeral cache only; loss is non-fatal (read below)
- **DNS/DHCP/NTP state**: Ephemeral; rebuilt from configuration

## PostgreSQL Backup & Restore

### Backup via pg_dump

```bash
# Backup a running manager database
pg_dump -h <postgres-host> -U <username> -d squawk_manager \
  --format=custom --compress=9 \
  --file=squawk-backup-$(date +%Y%m%d-%H%M%S).dump

# From inside K8s (if DB is not on the same cluster, port-forward first)
kubectl port-forward -n <postgres-namespace> <postgres-pod> 5432:5432 &
pg_dump -h localhost -U postgres -d squawk_manager \
  --format=custom --compress=9 \
  --file=squawk-backup.dump
```

### Restore via pg_restore

```bash
# Restore to a fresh database
createdb -h <postgres-host> -U <username> squawk_manager_restore
pg_restore -h <postgres-host> -U <username> -d squawk_manager_restore \
  --clean --if-exists squawk-backup.dump

# Verify restoration
psql -h <postgres-host> -U <username> -d squawk_manager_restore -c \
  "SELECT COUNT(*) FROM tokens; SELECT COUNT(*) FROM zones;"

# Once verified, cut over manager pods to the restored database
# via updating the manager-db Secret (see K8s Restore below)
```

## Kubernetes CronJob Backup

Deploy a nightly backup CronJob (adapt `<cluster>`, `<storage-class>`, `<retention-days>`):

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: squawk-backup
  namespace: squawk
spec:
  schedule: "0 2 * * *"  # 2 AM UTC daily
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: squawk-backup
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            fsGroup: 1000
          containers:
          - name: backup
            image: postgres:17-bookworm@sha256:<digest>
            env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: manager-db
                  key: password
            command:
            - /bin/bash
            - -c
            - |
              DB_URL=$(cat /etc/manager-db/url)
              DB_HOST=$(echo $DB_URL | sed 's/.*@//;s/:.*//;s/\/.*//')
              DB_USER=$(echo $DB_URL | sed 's|.*://||;s/:.*//')
              DB_NAME=$(echo $DB_URL | sed 's|.*/||')
              pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME \
                --format=custom --compress=9 \
                --file=/backups/squawk-$(date +\%Y\%m\%d-\%H\%M\%S).dump
              # Retain 7 days of backups
              find /backups -maxdepth 1 -name "squawk-*.dump" \
                -mtime +7 -delete
            volumeMounts:
            - name: manager-db
              mountPath: /etc/manager-db
              readOnly: true
            - name: backup-storage
              mountPath: /backups
            resources:
              requests:
                cpu: 200m
                memory: 256Mi
              limits:
                cpu: 500m
                memory: 512Mi
            securityContext:
              runAsNonRoot: true
              runAsUser: 1000
              allowPrivilegeEscalation: false
              readOnlyRootFilesystem: true
              capabilities:
                drop: [ALL]
          restartPolicy: OnFailure
          volumes:
          - name: manager-db
            secret:
              secretName: manager-db
          - name: backup-storage
            persistentVolumeClaim:
              claimName: squawk-backups
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: squawk-backups
  namespace: squawk
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: <storage-class>  # e.g., ebs-gp3, fast-ssd
  resources:
    requests:
      storage: 50Gi
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: squawk-backup
  namespace: squawk
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: squawk-backup
  namespace: squawk
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["manager-db"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: squawk-backup
  namespace: squawk
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: squawk-backup
subjects:
- kind: ServiceAccount
  name: squawk-backup
  namespace: squawk
```

## Valkey Persistence Stance

**Valkey in Squawk is ephemeral and cacheable.**

Valkey stores:
- DNS query result cache (TTL-managed)
- Manager session state (transient)
- Token verification cache (rebuilt on manager restart)

**Why not persistent:** Loss of Valkey causes only temporary slowdown. Missing cache entries are fetched upstream or recomputed. Manager can rebuild its session state. All critical state (tokens, zones, pools) lives in PostgreSQL.

**No RDB/AOF snapshots needed.** If cluster loss occurs:
1. Restart manager pod → reconnects to PostgreSQL
2. Restart dns-server pod → queries upstream without cache (slower, not broken)
3. Cache rebuilds over minutes as queries arrive

## Backup Retention & Cleanup

- **Daily backups**: 7 days on-site PVC
- **Weekly archives**: Move 1-week-old backups to object storage (S3, GCS, Blob) weekly via a separate Job
- **Off-site retention**: 90 days minimum
- **Test restores**: Monthly restore-drill on a staging database

## RPO/RTO Table

| Component | RPO (Max Data Loss) | RTO (Recovery Time) | Notes |
|-----------|--------|---------|-------|
| **Tokens** | Nightly backup (~24h) | 15-20 min (pg_restore + pod restart) | Stored in PostgreSQL only |
| **Zones** | Nightly backup (~24h) | 15-20 min | DNS data in PostgreSQL |
| **DHCP Pools** | Nightly backup (~24h) | 15-20 min | Lease state ephemeral |
| **NTP Config** | Nightly backup (~24h) | 5 min (pod restart) | Config-driven, no state |
| **Cache** | 0 (no persistence) | 0-5 min (cache rebuilt) | No data loss; performance impact only |

**In-flight requests:** DNS/DHCP queries in-flight during outage are retried by clients. No loss of query history (not stored durably).

## Restore-Drill Checklist

**Monthly:** Verify backup integrity and restore procedures. Schedule outside business hours.

- [ ] Download latest backup from PVC/object storage
- [ ] Spin up a staging PostgreSQL instance (same major version)
- [ ] Run `pg_restore` to a test database
- [ ] Query test database: `SELECT COUNT(*) FROM tokens, zones, etc.`
- [ ] Verify row counts match production baseline (document expected values)
- [ ] Simulate manager restart against restored DB (deploy staging manager pod with restored DB_URL)
- [ ] Verify manager health checks pass
- [ ] Spot-check a few tokens: generate DNS query, verify token validation succeeds
- [ ] Document restore time and any issues in ops log
- [ ] Clean up test instances

**Full disaster scenario:** Quarterly, restore to a clean K8s namespace and verify the entire stack:

1. Restore manager database from backup
2. Deploy manager, dns-server, dhcp-server, ntp-server against restored DB
3. Issue test queries; verify responses correct
4. Document full RTO

## Off-Site Backup Archive

```bash
# Weekly archive script (add as a CronJob at 3 AM Sunday)
#!/bin/bash
WEEK=$(date +%G-W%V)
aws s3 cp /backups/squawk-*.dump s3://<backup-bucket>/squawk/${WEEK}/ \
  --sse AES256 --storage-class GLACIER
find /backups -maxdepth 1 -name "squawk-*.dump" -mtime +7 -delete
```

Lifecycle policy on S3:
- **Transition to GLACIER after 30 days**
- **Delete after 90 days**
