import {
    td,
    BufferReader,
    Endian,
    getRandomByteBuffer,
    kexToPayload,
    toUInt32Buffer,
    type Kex,
} from "./utils";
import * as assert from "node:assert";

const socket = await Bun.connect({
    hostname: "localhost",
    port: 8080,

    socket: {
        async data(socket, data) {
            console.log("");
            console.log("Data Received");

            const dataDecoded = td.decode(data);
            if (dataDecoded.startsWith("SSH-")) {
                console.log("Server version buffer received");
                const file = Bun.file("./kex.bin");
                const bytes = await file.arrayBuffer();

                socket.write(bytes);
                console.log("SENDING SSH_MSG_KEXINIT");
                return;
            }

            const dr = new BufferReader(data);

            const packet_len = dr.readUInt32();
            const padding_len = dr.readByte();
            const payload = dr.readBytes(packet_len - padding_len - 1);

            const pr = new BufferReader(payload);

            console.log("Event based payload received");

            if (pr.readByte() == 20) {
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

                const _first_kex_packet_follows = pr.readBoolean();

                assert.equal(
                    pr.readUInt32(),
                    0,
                    "Failed to parse 'KEXINIT' message future extension bool is not '0'"
                );

                console.log("Event: SSH_MSG_KEXINIT");
                console.log({ nameLists, cookie });
                Bun.write("kex.json", JSON.stringify(nameLists, ))

                // socket.write(
                //     Buffer.from([
                //         20,
                //         ...getRandomByteBuffer(16), // Cookie
                //         ...kexToPayload(getServerKex()),
                //         0,
                //         ...toUInt32Buffer(0),
                //         ...Buffer.from("\r\n"),
                //     ])
                // );
                if (pr.rest().length == 0) {
                    console.log("End of kex parsing");
                    return;
                }

                console.log("Rest input", pr.rest());
            }

            console.log({ packet_len, padding_len, payload });

            console.log("Something else...");
        },
        open(socket) {
            console.log("Sending version buffer");
            socket.write(
                Buffer.from([
                    83, 83, 72, 45, 50, 46, 48, 45, 79, 112, 101, 110, 83, 83,
                    72, 95, 102, 111, 114, 95, 87, 105, 110, 100, 111, 119, 115,
                    95, 56, 46, 54, 13, 10,
                ])
            );
        },
    },
});

function getClientKex(): Kex {
    return {
        kex_algorithms: [
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group18-sha512",
            "diffie-hellman-group14-sha256",
            "ext-info-c",
        ],
        server_host_key_algorithms: [
            "ssh-ed25519-cert-v01@openssh.com",
            "ecdsa-sha2-nistp256-cert-v01@openssh.com",
            "ecdsa-sha2-nistp384-cert-v01@openssh.com",
            "ecdsa-sha2-nistp521-cert-v01@openssh.com",
            "sk-ssh-ed25519-cert-v01@openssh.com",
            "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
            "rsa-sha2-512-cert-v01@openssh.com",
            "rsa-sha2-256-cert-v01@openssh.com",
            "ssh-rsa-cert-v01@openssh.com",
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "sk-ssh-ed25519@openssh.com",
            "sk-ecdsa-sha2-nistp256@openssh.com",
            "rsa-sha2-512",
            "rsa-sha2-256",
            "ssh-rsa",
        ],
        encryption_algorithms_client_to_server: [
            "chacha20-poly1305@openssh.com",
            "aes128-ctr",
            "aes192-ctr",
            "aes256-ctr",
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com",
        ],
        encryption_algorithms_server_to_client: [
            "chacha20-poly1305@openssh.com",
            "aes128-ctr",
            "aes192-ctr",
            "aes256-ctr",
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com",
        ],
        mac_algorithms_client_to_server: [
            "umac-64-etm@openssh.com",
            "umac-128-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha1-etm@openssh.com",
            "umac-64@openssh.com",
            "umac-128@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-512",
            "hmac-sha1",
        ],
        mac_algorithms_server_to_client: [
            "umac-64-etm@openssh.com",
            "umac-128-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha1-etm@openssh.com",
            "umac-64@openssh.com",
            "umac-128@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-512",
            "hmac-sha1",
        ],
        compression_algorithms_client_to_server: [
            "none",
            "zlib@openssh.com",
            "zlib",
        ],
        compression_algorithms_server_to_client: [
            "none",
            "zlib@openssh.com",
            "zlib",
        ],
        languages_client_to_server: [""],
        languages_server_to_client: [""],
    };
}
