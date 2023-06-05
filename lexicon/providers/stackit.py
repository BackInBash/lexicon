"""Module provider for STACKIT"""
import json
import logging

import requests

from lexicon.exceptions import AuthenticationError
from lexicon.providers.base import Provider as BaseProvider

LOGGER = logging.getLogger(__name__)
NAMESERVER_DOMAINS = ["dns.stackit.cloud"]


def provider_parser(subparser):
    """Configure a provider parser for STACKIT"""
    subparser.add_argument("--auth-token", help="Specify STACKIT DNS API token")


class Provider(BaseProvider):
    """
    Implements the STACKIT DNS Provider using the service https://docs.stackit.cloud/stackit/en/dns-123568850.html
    """

    API_VERSION = "1.0"

    """Provider class for STACKIT"""

    def __init__(self, config):
        super(Provider, self).__init__(config)
        self.domain_id = None
        self.api_endpoint = "https://dns.api.stackit.cloud/v1/projects/"

    def _authenticate(self):
        # parse projectID from auth token
        self.api_endpoint = self.api_endpoint+self._extract_project_id()
        provider = self._get_zone_by_domain(self.domain)
        self.domain_id = provider["id"]

    def _extract_project_id(self):
        import json
        import base64
        # get auth token + make it base64
        if len(self._get_provider_option("auth_token").split('.')) > 0:
            return ""
        split = self._get_provider_option("auth_token").split('.')[1]+"=="
        # decode token + load content as json
        json = json.loads(base64.b64decode(split.encode("ascii")).decode("ascii"))
        return json["stackit/project/project.id"]

    def _create_record(self, rtype, name, content):
        """
        Creates a DNS record, if a record with type, name and content exits, do nothing
        :returns: A json string containing the resulting record
        :rtype: str
        """

        data = {
            "name": self._get_record_name(self.domain, name),
            "type": rtype,
            "records": list(content),
        }
        if self._get_lexicon_option("ttl"):
            data["ttl"] = self._get_lexicon_option("ttl")

        records = self._list_records(rtype=rtype, name=name, content=content)
        if len(records) >= 1:
            for record in records:
                LOGGER.warning(
                    "Duplicate record %s %s %s with id %s",
                    rtype,
                    name,
                    content,
                    record["id"],
                )
            return True
        self._post("/zones/"+self.domain_id+"/rrsets", data)
        return True

    def _list_records(self, rtype=None, name=None, content=None):
        """
        List all records, filterable by type, name and content
        :rtype: list
        :returns: list of records, might be empty
        """
        filter_obj = {"active[eq]": "true"}
        payload = self._get("/zones/"+self.domain_id+"/rrsets", filter_obj)
        records = map(self._stackit_record_to_lexicon_record, payload["rrSets"])
        filtered_records = self._filter_records(
            records, rtype, name if name is not None else None, content
        )

        return filtered_records

    def _filter_records(self, records, rtype=None, name=None, content=None):
        return [
            record
            for record in records
            if (rtype is None or record["type"] == rtype)
            and (name is None or record["name"] == self._full_name(name))
            and (content is None or record["records"]["content"] == content)
        ]

    def _update_record(self, identifier, rtype=None, name=None, content=None):
        """
        Create or update a record.
        :rtype: bool
        :returns: Boolean indicating success
        """
        data = {
            "type": rtype,
            "name": self._get_record_name(self.domain, name),
            "records": list(content),
        }
        if self._get_lexicon_option("ttl"):
            data["ttl"] = self._get_lexicon_option("ttl")
        update_identifier = identifier
        if update_identifier is None:
            records = self._list_records(rtype, name)
            if len(records) == 1:
                update_identifier = records[0]["id"]
            elif len(records) < 1:
                raise Exception(
                    "No records found matching type, name and content - won't update"
                )
            else:
                raise Exception(
                    "Multiple records found matching type, name and content - won't update"
                )
        self._put(f"/zones/"+self.domain_id+"/rrsets/{update_identifier}", data)
        return True

    def _delete_record(self, identifier=None, rtype=None, name=None, content=None):
        """
        Delete an existing record. If record does not exist, do nothing.
        :rtype: bool
        :returns: Boolean indicating success
        """
        delete_record_ids = []
        if identifier is None:
            records = self._list_records(rtype, name, content)
            delete_record_ids = [record["id"] for record in records]
        else:
            delete_record_ids.append(identifier)

        for record_id in delete_record_ids:
            self._delete(f"/zones/"+self.domain_id+"/rrsets/{record_id}")
        return True

    # Helpers
    def _request(self, action="GET", url="/", data=None, query_params=None):
        if data is None:
            data = {}
        if query_params is None:
            query_params = {}
        response = requests.request(
            action,
            self.api_endpoint + url,
            params=query_params,
            data=json.dumps(data),
            headers={
                "Authorization": "Bearer "+self._get_provider_option("auth_token"),
                "Content-Type": "application/json",
            },
        )
        # if the request fails for any reason, throw an error.
        response.raise_for_status()
        return response.json()

    def _get_zone_by_domain(self, domain):
        """
        Requests all dns zones from your STACKIT project and searches for a specific
        one to determine the ID of it
        :param domain: Name of domain for which dns zone should be searched
        :rtype: dict
        :return: The dictionary of the zone with ``domain`` in the 'name' key
        :raises Exception: If no zone was found
        :raises KeyError, ValueError: If the response is malformed
        :raises urllib.error.HttpError: If request to /zones did not return 200
        """
        zfilter_obj = {"dnsName[eq]": domain, "active[eq]": "true"}
        payload = self._get("/zones", zfilter_obj)
        zones = payload["zones"]
        for zone in zones:
            if zone["dnsName"] == domain:
                return zone
        raise AuthenticationError(f"No zone was found in account matching {domain}")

    def _get_record_name(self, domain, record_name):
        """
        Get the name attribute appropriate for STACKIT api. This means it's the name
        without domain name if record name ends with managed domain name else a fqdn
        :param domain: Name of domain for which dns zone should be searched
        :param record_name: The record name to convert
        :rtype: str
        :return: The record name in an appropriate format for hetzner api
        """
        if record_name.rstrip(".").endswith(domain):
            record_name = self._relative_name(record_name)
        return record_name

    @staticmethod
    def _pretty_json(data):
        return json.dumps(data, sort_keys=True, indent=4, separators=(",", ": "))

    def _stackit_record_to_lexicon_record(self, stackit_record):
        lexicon_record = {
            "id": stackit_record["id"],
            "name": self._full_name(stackit_record["name"]),
            "content": stackit_record["records"],
            "type": stackit_record["type"],
        }
        if "ttl" in stackit_record:
            lexicon_record["ttl"] = stackit_record["ttl"]
        return lexicon_record
