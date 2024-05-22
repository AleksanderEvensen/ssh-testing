import * as assert from "node:assert";
import { BufferReader, td, Endian, kexToPayload, getRandomByteBuffer, toUInt32Buffer } from "./utils";
import type { Kex } from "./utils";

type SocketData = { sessionId: string };

Bun.listen<SocketData>({
    hostname: "localhost",
    port: 8081,
    socket: {
        data(socket, data) {
            // console.log("Data Received");
            // console.log("Socket", socket);
            // console.log("Raw Data", data);
            // console.log("Data str serialized", td.decode(data));
            console.log("");
            console.log("Data received from client");
            const dataDecoded = td.decode(data);


            if (dataDecoded.startsWith("SSH-")) {
                console.log("Version Check detected")
                // Confirm server ssh version
                const versionBuffer = Buffer.from(
                    "SSH-2.0-Custom_SSH_Server_Bun\r\n",
                    "ascii"
                );
                // console.log("Version buffer", versionBuffer);
                socket.write(versionBuffer);
                console.log("Sending version buffer");
                return;
            }

            const dr = new BufferReader(data);

            const packet_len = dr.readUInt32();
            const padding_len = dr.readByte();
            const payload = dr.readBytes(packet_len - padding_len - 1);

            const pr = new BufferReader(payload);

            console.log("Event based payload received")

            if (pr.readByte() == 20) {
                console.log("Data len", data.length);
                Bun.write("kex.bin", data);
                const cookie = pr.readBytes(16);

                const kex_algorithms = pr
                    .readString(pr.readUInt32())
                    .split(",");
                const server_host_key_algorithms = pr
                    .readString(pr.readUInt32())
                    .split(",");
                const encryption_algorithms_client_to_server = pr
                    .readString(pr.readUInt32())
                    .split(",");
                const encryption_algorithms_server_to_client = pr
                    .readString(pr.readUInt32())
                    .split(",");
                const mac_algorithms_client_to_server = pr
                    .readString(pr.readUInt32())
                    .split(",");
                const mac_algorithms_server_to_client = pr
                    .readString(pr.readUInt32())
                    .split(",");
                const compression_algorithms_client_to_server = pr
                    .readString(pr.readUInt32())
                    .split(",");
                const compression_algorithms_server_to_client = pr
                    .readString(pr.readUInt32())
                    .split(",");
                const languages_client_to_server = pr
                    .readString(pr.readUInt32())
                    .split(",");
                const languages_server_to_client = pr
                    .readString(pr.readUInt32())
                    .split(",");

                const nameLists = {
                    kex_algorithms,
                    server_host_key_algorithms,
                    encryption_algorithms_client_to_server,
                    encryption_algorithms_server_to_client,
                    mac_algorithms_client_to_server,
                    mac_algorithms_server_to_client,
                    compression_algorithms_client_to_server,
                    compression_algorithms_server_to_client,
                    languages_client_to_server,
                    languages_server_to_client,
                };
                // console.log(nameLists);

                const _first_kex_packet_follows = pr.readBoolean();

                assert.equal(
                    pr.readUInt32(),
                    0,
                    "Failed to parse 'KEXINIT' message future extension bool is not '0'"
                );

                console.log("Event: SSH_MSG_KEXINIT");

                socket.write(
                    Buffer.from([
                        20,
                        ...getRandomByteBuffer(16), // Cookie
                        ...kexToPayload(getServerKex()),
                        0,
                        ...toUInt32Buffer(0),
                        ...Buffer.from("\r\n"),
                    ])
                );
                console.log("Sending server kex");
                if (pr.rest().length == 0) return;
            }

            console.log({ packet_len, padding_len, payload });

            console.log("Something else...");
        },
        open(socket) {
            console.log("Sokcet connection opened");
            socket.data = { sessionId: crypto.randomUUID() };
            // console.log("open", socket);
        },
    },
});



function getServerKex(): Kex {
    return {
        kex_algorithms: ["curve25519-sha256"],
        server_host_key_algorithms: ["ssh-ed25519-cert-v01@openssh.com"],
        encryption_algorithms_client_to_server: [
            "chacha20-poly1305@openssh.com",
        ],
        encryption_algorithms_server_to_client: [
            "chacha20-poly1305@openssh.com",
        ],
        mac_algorithms_client_to_server: ["umac-64-etm@openssh.com"],
        mac_algorithms_server_to_client: ["umac-64-etm@openssh.com"],
        compression_algorithms_client_to_server: ["none"],
        compression_algorithms_server_to_client: ["none"],
        languages_client_to_server: [""],
        languages_server_to_client: [""],
    };
}





console.log("Running server");
