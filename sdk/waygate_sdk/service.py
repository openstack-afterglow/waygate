"""Waygate service descriptor for openstacksdk."""

from openstack import service_description

from waygate_sdk.proxy import Proxy


class WaygateService(service_description.ServiceDescription):
    def __init__(self):
        super().__init__("waygate", supported_versions={"1": Proxy})
