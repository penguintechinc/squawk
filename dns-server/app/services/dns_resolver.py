"""
DNS Resolver Service
Resolves DNS queries using dnspython.
"""
import dns.resolver
import dns.rdatatype
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class DNSResolver:
    """DNS resolution service."""

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    async def resolve(self, domain: str, record_type: str = 'A') -> Dict[str, Any]:
        """
        Resolve DNS query.

        Args:
            domain: Domain name to resolve
            record_type: DNS record type (A, AAAA, CNAME, MX, TXT, etc.)

        Returns:
            RFC 1035 compliant DNS response
        """
        try:
            # Convert record type string to dns.rdatatype
            try:
                rdtype = dns.rdatatype.from_text(record_type.upper())
            except Exception:
                logger.error(f"Invalid record type: {record_type}")
                return {
                    'Status': 2,  # SERVFAIL
                    'Question': [{'name': domain, 'type': record_type}],
                    'Answer': []
                }

            # Perform DNS query
            answers = self.resolver.resolve(domain, rdtype)

            # Build response
            answer_records = []
            for rdata in answers:
                answer_records.append({
                    'name': domain,
                    'type': record_type,
                    'TTL': answers.rrset.ttl,
                    'data': str(rdata)
                })

            return {
                'Status': 0,  # NOERROR
                'Question': [{'name': domain, 'type': record_type}],
                'Answer': answer_records
            }

        except dns.resolver.NXDOMAIN:
            logger.info(f"NXDOMAIN: {domain}")
            return {
                'Status': 3,  # NXDOMAIN
                'Question': [{'name': domain, 'type': record_type}],
                'Answer': []
            }

        except dns.resolver.Timeout:
            logger.warning(f"DNS query timeout for {domain}")
            return {
                'Status': 2,  # SERVFAIL
                'Question': [{'name': domain, 'type': record_type}],
                'Answer': []
            }

        except dns.resolver.NoAnswer:
            logger.info(f"No answer for {domain} {record_type}")
            return {
                'Status': 0,  # NOERROR but no answers
                'Question': [{'name': domain, 'type': record_type}],
                'Answer': []
            }

        except Exception as e:
            logger.error(f"DNS resolution error for {domain}: {e}")
            return {
                'Status': 2,  # SERVFAIL
                'Question': [{'name': domain, 'type': record_type}],
                'Answer': []
            }

    def resolve_custom_zone(self, domain: str, record_type: str, zone_records: List[Dict]) -> Dict[str, Any]:
        """
        Resolve from custom zone records (Manager-provided zones).

        Args:
            domain: Domain to resolve
            record_type: Record type
            zone_records: List of zone records from Manager

        Returns:
            DNS response
        """
        matching_records = []

        for record in zone_records:
            if record['name'] == domain and record['type'] == record_type:
                matching_records.append({
                    'name': domain,
                    'type': record_type,
                    'TTL': record.get('ttl', 300),
                    'data': record['value']
                })

        if matching_records:
            return {
                'Status': 0,  # NOERROR
                'Question': [{'name': domain, 'type': record_type}],
                'Answer': matching_records
            }
        else:
            return {
                'Status': 3,  # NXDOMAIN
                'Question': [{'name': domain, 'type': record_type}],
                'Answer': []
            }
