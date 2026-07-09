package k8swatcher

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/penguintechinc/squawk/squawk-client-go/pkg/metrics"
	"github.com/penguintechinc/squawk/squawk-client-go/pkg/zonecache"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Watcher watches Kubernetes Services and Endpoints and updates a DNS zone cache.
type Watcher struct {
	cache            *zonecache.Cache
	client           kubernetes.Interface
	metrics          *metrics.Metrics
	clusterDomain    string
	stopCh           chan struct{}
	serviceInformer  cache.SharedIndexInformer
	endpointInformer cache.SharedIndexInformer
}

// New creates a new Kubernetes DNS watcher.
func New(cache *zonecache.Cache, client kubernetes.Interface, clusterDomain string) *Watcher {
	return NewWithMetrics(cache, client, clusterDomain, nil)
}

// NewWithMetrics creates a new Kubernetes DNS watcher with optional metrics.
func NewWithMetrics(cache *zonecache.Cache, client kubernetes.Interface, clusterDomain string, m *metrics.Metrics) *Watcher {
	if clusterDomain == "" {
		clusterDomain = "cluster.local"
	}
	return &Watcher{
		cache:         cache,
		client:        client,
		metrics:       m,
		clusterDomain: clusterDomain,
		stopCh:        make(chan struct{}),
	}
}

// Start begins watching Kubernetes Services and Endpoints.
func (w *Watcher) Start(ctx context.Context) error {
	// Record sync start time
	syncStart := time.Now()

	// Create informers for Services and Endpoints
	serviceListWatcher := cache.NewListWatchFromClient(
		w.client.CoreV1().RESTClient(),
		"services",
		"",
		fields.Everything(),
	)
	endpointListWatcher := cache.NewListWatchFromClient(
		w.client.CoreV1().RESTClient(),
		"endpoints",
		"",
		fields.Everything(),
	)

	// Create informers
	w.serviceInformer = cache.NewSharedIndexInformer(
		serviceListWatcher,
		&corev1.Service{},
		0,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	w.endpointInformer = cache.NewSharedIndexInformer(
		endpointListWatcher,
		&corev1.Endpoints{},
		0,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	// Add event handlers
	w.serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.handleServiceAdd,
		UpdateFunc: w.handleServiceUpdate,
		DeleteFunc: w.handleServiceDelete,
	})

	w.endpointInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.handleEndpointAdd,
		UpdateFunc: w.handleEndpointUpdate,
		DeleteFunc: w.handleEndpointDelete,
	})

	// Start informers
	go w.serviceInformer.Run(w.stopCh)
	go w.endpointInformer.Run(w.stopCh)

	// Wait for caches to sync
	if !cache.WaitForCacheSync(w.stopCh, w.serviceInformer.HasSynced, w.endpointInformer.HasSynced) {
		return fmt.Errorf("failed to wait for cache sync")
	}

	// Record sync duration
	if w.metrics != nil {
		w.metrics.K8sWatcherSyncDuration.Observe(time.Since(syncStart).Seconds())
	}

	log.Println("Kubernetes DNS watcher started")
	return nil
}

// Stop shuts down the watcher.
func (w *Watcher) Stop() {
	close(w.stopCh)
	log.Println("Kubernetes DNS watcher stopped")
}

// handleServiceAdd processes a new Service.
func (w *Watcher) handleServiceAdd(obj interface{}) {
	svc := obj.(*corev1.Service)
	w.updateServiceRecords(svc)
	if w.metrics != nil {
		w.metrics.K8sWatcherEventsTotal.WithLabelValues("service", "add").Inc()
		w.metrics.ZoneEntries.Set(float64(w.cache.Len()))
	}
}

// handleServiceUpdate processes an updated Service.
func (w *Watcher) handleServiceUpdate(oldObj, newObj interface{}) {
	svc := newObj.(*corev1.Service)
	w.updateServiceRecords(svc)
	if w.metrics != nil {
		w.metrics.K8sWatcherEventsTotal.WithLabelValues("service", "update").Inc()
		w.metrics.ZoneEntries.Set(float64(w.cache.Len()))
	}
}

// handleServiceDelete removes records for a deleted Service.
func (w *Watcher) handleServiceDelete(obj interface{}) {
	svc := obj.(*corev1.Service)
	svcName := svc.Name
	namespace := svc.Namespace

	// Delete A record for the Service
	aRecordName := fmt.Sprintf("%s.%s.svc.%s.", svcName, namespace, w.clusterDomain)
	w.cache.Delete(aRecordName)

	// Delete SRV records for each port
	for _, port := range svc.Spec.Ports {
		if port.Name != "" {
			proto := "tcp"
			if port.Protocol == corev1.ProtocolUDP {
				proto = "udp"
			}
			srvRecordName := fmt.Sprintf("_%s._%s.%s.%s.svc.%s.", port.Name, proto, svcName, namespace, w.clusterDomain)
			w.cache.Delete(srvRecordName)
		}
	}

	if w.metrics != nil {
		w.metrics.K8sWatcherEventsTotal.WithLabelValues("service", "delete").Inc()
		w.metrics.ZoneEntries.Set(float64(w.cache.Len()))
	}

	log.Printf("Removed DNS records for Service %s/%s", namespace, svcName)
}

// updateServiceRecords synthesizes DNS records for a Service.
func (w *Watcher) updateServiceRecords(svc *corev1.Service) {
	svcName := svc.Name
	namespace := svc.Namespace
	clusterIP := svc.Spec.ClusterIP

	// Skip headless services (ClusterIP = "None") for A records
	if clusterIP != "None" && clusterIP != "" {
		aRecordName := fmt.Sprintf("%s.%s.svc.%s.", svcName, namespace, w.clusterDomain)
		ip := net.ParseIP(clusterIP)
		if ip != nil {
			rrs := []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   aRecordName,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    30,
					},
					A: ip.To4(),
				},
			}
			w.cache.Set(aRecordName, rrs)
		}
	}

	// Synthesize SRV records for named ports
	for _, port := range svc.Spec.Ports {
		if port.Name != "" {
			proto := "tcp"
			if port.Protocol == corev1.ProtocolUDP {
				proto = "udp"
			}
			srvRecordName := fmt.Sprintf("_%s._%s.%s.%s.svc.%s.", port.Name, proto, svcName, namespace, w.clusterDomain)
			targetName := fmt.Sprintf("%s.%s.svc.%s.", svcName, namespace, w.clusterDomain)

			rrs := []dns.RR{
				&dns.SRV{
					Hdr: dns.RR_Header{
						Name:   srvRecordName,
						Rrtype: dns.TypeSRV,
						Class:  dns.ClassINET,
						Ttl:    30,
					},
					Priority: 10,
					Weight:   100,
					Port:     uint16(port.Port),
					Target:   targetName,
				},
			}
			w.cache.Set(srvRecordName, rrs)
		}
	}

	log.Printf("Updated DNS records for Service %s/%s", namespace, svcName)
}

// handleEndpointAdd processes a new Endpoints object.
func (w *Watcher) handleEndpointAdd(obj interface{}) {
	ep := obj.(*corev1.Endpoints)
	w.updateEndpointRecords(ep)
	if w.metrics != nil {
		w.metrics.K8sWatcherEventsTotal.WithLabelValues("endpoints", "add").Inc()
		w.metrics.ZoneEntries.Set(float64(w.cache.Len()))
	}
}

// handleEndpointUpdate processes an updated Endpoints object.
func (w *Watcher) handleEndpointUpdate(oldObj, newObj interface{}) {
	ep := newObj.(*corev1.Endpoints)
	w.updateEndpointRecords(ep)
	if w.metrics != nil {
		w.metrics.K8sWatcherEventsTotal.WithLabelValues("endpoints", "update").Inc()
		w.metrics.ZoneEntries.Set(float64(w.cache.Len()))
	}
}

// handleEndpointDelete removes records for deleted Endpoints.
func (w *Watcher) handleEndpointDelete(obj interface{}) {
	ep := obj.(*corev1.Endpoints)
	epName := ep.Name
	namespace := ep.Namespace

	// For headless services, delete pod A records
	for _, subset := range ep.Subsets {
		for _, addr := range subset.Addresses {
			if addr.TargetRef != nil && addr.TargetRef.Name != "" {
				podName := addr.TargetRef.Name
				podRecordName := fmt.Sprintf("%s.%s.pod.%s.", podName, namespace, w.clusterDomain)
				w.cache.Delete(podRecordName)
			}
		}
	}

	// For headless services, delete service A records pointing to endpoint IPs
	svcRecordName := fmt.Sprintf("%s.%s.svc.%s.", epName, namespace, w.clusterDomain)
	w.cache.Delete(svcRecordName)

	if w.metrics != nil {
		w.metrics.K8sWatcherEventsTotal.WithLabelValues("endpoints", "delete").Inc()
		w.metrics.ZoneEntries.Set(float64(w.cache.Len()))
	}

	log.Printf("Removed DNS records for Endpoints %s/%s", namespace, epName)
}

// isHeadless returns true if the Service corresponding to this Endpoints object is headless.
func (w *Watcher) isHeadless(namespace, name string) bool {
	key := namespace + "/" + name
	item, exists, err := w.serviceInformer.GetStore().GetByKey(key)
	if err != nil || !exists {
		return false
	}
	svc, ok := item.(*corev1.Service)
	if !ok {
		return false
	}
	return svc.Spec.ClusterIP == "None"
}

// updateEndpointRecords synthesizes DNS records for Endpoints.
func (w *Watcher) updateEndpointRecords(ep *corev1.Endpoints) {
	epName := ep.Name
	namespace := ep.Namespace
	headless := w.isHeadless(namespace, epName)
	var headlessARecords []dns.RR

	for _, subset := range ep.Subsets {
		for _, addr := range subset.Addresses {
			ip := net.ParseIP(addr.IP)
			if ip == nil {
				continue
			}

			// Pod A record: <podname>.<ns>.pod.cluster.local.
			if addr.TargetRef != nil && addr.TargetRef.Name != "" {
				podName := addr.TargetRef.Name
				podRecordName := fmt.Sprintf("%s.%s.pod.%s.", podName, namespace, w.clusterDomain)
				w.cache.Set(podRecordName, []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   podRecordName,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    30,
						},
						A: ip.To4(),
					},
				})
			}

			// For headless services only: accumulate endpoint IPs as service A records.
			if headless {
				svcFQDN := fmt.Sprintf("%s.%s.svc.%s.", epName, namespace, w.clusterDomain)
				headlessARecords = append(headlessARecords, &dns.A{
					Hdr: dns.RR_Header{
						Name:   svcFQDN,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    30,
					},
					A: ip.To4(),
				})
			}
		}
	}

	if headless && len(headlessARecords) > 0 {
		svcRecordName := fmt.Sprintf("%s.%s.svc.%s.", epName, namespace, w.clusterDomain)
		w.cache.Set(svcRecordName, headlessARecords)
	}

	log.Printf("Updated DNS records for Endpoints %s/%s", namespace, epName)
}
