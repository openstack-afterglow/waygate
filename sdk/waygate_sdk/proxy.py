"""OpenStack SDK proxy for Waygate v1."""

from __future__ import annotations

from urllib.parse import quote

from openstack import proxy


def _segment(value: object) -> str:
    return quote(str(value), safe="")


class Proxy(proxy.Proxy):
    def _json_request(self, method: str, path: str, *, body: dict | None = None):
        kwargs = {"json": body} if body is not None else {}
        response = self.request(path, method, raise_exc=True, **kwargs)
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    def servers(self):
        return self._json_request("GET", "/v1/servers")

    def get_server(self, server_id):
        return self._json_request("GET", f"/v1/servers/{_segment(server_id)}")

    def create_server(self, **attrs):
        return self._json_request("POST", "/v1/servers", body=attrs)

    def delete_server(self, server_id):
        return self._json_request("DELETE", f"/v1/servers/{_segment(server_id)}")

    def clients(self, server_id):
        return self._json_request("GET", f"/v1/servers/{_segment(server_id)}/clients")

    def create_client(self, server_id, **attrs):
        return self._json_request("POST", f"/v1/servers/{_segment(server_id)}/clients", body=attrs)

    def update_client(self, server_id, client_id, **attrs):
        return self._json_request(
            "PATCH",
            f"/v1/servers/{_segment(server_id)}/clients/{_segment(client_id)}",
            body=attrs,
        )

    def delete_client(self, server_id, client_id):
        return self._json_request(
            "DELETE",
            f"/v1/servers/{_segment(server_id)}/clients/{_segment(client_id)}",
        )

    def client_config(self, server_id, client_id):
        response = self.request(
            f"/v1/servers/{_segment(server_id)}/clients/{_segment(client_id)}/config",
            "GET",
            raise_exc=True,
        )
        return response.text

    def networks(self, server_id):
        return self._json_request("GET", f"/v1/servers/{_segment(server_id)}/networks")

    def attach_network(self, server_id, **attrs):
        return self._json_request("POST", f"/v1/servers/{_segment(server_id)}/networks", body=attrs)

    def detach_network(self, server_id, attachment_id):
        return self._json_request(
            "DELETE",
            f"/v1/servers/{_segment(server_id)}/networks/{_segment(attachment_id)}",
        )

    def export_server(self, server_id, **attrs):
        return self._json_request("POST", f"/v1/servers/{_segment(server_id)}/export", body=attrs)

    def import_server(self, server_id, **attrs):
        return self._json_request("POST", f"/v1/servers/{_segment(server_id)}/import", body=attrs)
