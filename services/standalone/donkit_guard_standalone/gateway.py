"""The gRPC server agentgateway calls: ext_proc for the LLM route, ExtMcp for the MCP route."""

from __future__ import annotations

from typing import TYPE_CHECKING

import grpc

from donkit_guard_standalone.extmcp import McpPolicy
from donkit_guard_standalone.extproc import ExternalProcessor
from donkit_guard_standalone.proto import ext_mcp_pb2_grpc, ext_proc_pb2_grpc

if TYPE_CHECKING:
    from donkit_guard_standalone.service import GuardService

# Room for the protocol's own framing around the largest body the guard accepts.
_FRAMING_BYTES = 64 * 1024
_STOP_GRACE_S = 5.0


class GatewayServer:
    def __init__(self, server: grpc.aio.Server, port: int) -> None:
        self._server = server
        self.port = port

    @classmethod
    async def start(cls, service: GuardService) -> GatewayServer:
        settings = service.settings
        limit = settings.max_body_bytes + _FRAMING_BYTES
        server = grpc.aio.server(
            options=[
                ("grpc.max_receive_message_length", limit),
                ("grpc.max_send_message_length", limit),
            ]
        )
        ext_proc_pb2_grpc.add_ExternalProcessorServicer_to_server(
            ExternalProcessor(service), server
        )
        ext_mcp_pb2_grpc.add_ExtMcpServicer_to_server(McpPolicy(service), server)
        port = server.add_insecure_port(f"{settings.grpc_host}:{settings.grpc_port}")
        await server.start()
        return cls(server, port)

    async def stop(self) -> None:
        await self._server.stop(grace=_STOP_GRACE_S)
