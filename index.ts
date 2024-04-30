import * as assert from 'node:assert';

type SocketData = { sessionId: string };

const td = new TextDecoder();

enum Endian {
    Little,
    Big,
}

class BufferReader {

    private buffer: Buffer;
    private cursor: number;

    constructor(buffer: Buffer) {
        this.buffer = buffer;
        this.cursor = 0;
    }


    readString(length: number) {
        const strBuffer = this.buffer.subarray(this.cursor, this.cursor + length);
        this.cursor += length;
        return td.decode(strBuffer);
    }

    readUInt32(endian: Endian = Endian.Big) {
        const func = endian == Endian.Big ? this.buffer.readUInt32BE.bind(this.buffer) : this.buffer.readUInt32LE.bind(this.buffer);
        this.cursor += 4;
        return func(this.cursor - 4);
    }

    readBytes(length: number) {
        const bytes = this.buffer.subarray(this.cursor, this.cursor + length);
        this.cursor += length;
        return bytes;
    }
    readByte() {
        const byte = this.buffer[this.cursor];
        this.cursor += 1;
        return byte;
    }

    readBoolean() {
        const boolByte = this.readByte();
        return boolByte > 0;
    }

    rest() {
        return this.buffer.subarray(this.cursor);
    }
}




Bun.listen<SocketData>({
    hostname: "localhost",
    port: 8080,
    socket: {
        data(socket, data) {
            
            console.log("Data Received");
            console.log("Socket", socket);
            console.log("Raw Data", data);
            console.log("Data str serialized", td.decode(data));

            const dataDecoded = td.decode(data);


            
            if (dataDecoded.startsWith("SSH-")) { // Confirm server ssh version
                const versionBuffer = Buffer.from("SSH-2.0-Custom_SSH_Server_Bun\r\n", "ascii");
                console.log("Version buffer", versionBuffer);
                socket.write(versionBuffer);
                return;
            }

            const dr = new BufferReader(data);

            


            const packet_len = dr.readUInt32();
            const padding_len = dr.readByte();
            const payload = dr.readBytes(packet_len - padding_len - 1);


            const pr = new BufferReader(payload);
            
            if (pr.readByte() == 20) {
                const cookie = pr.readBytes(16);
                
                const kex_algorithms = pr.readString(pr.readUInt32()).split(',');
                const server_host_key_algorithms = pr.readString(pr.readUInt32()).split(',');
                const encryption_algorithms_client_to_server = pr.readString(pr.readUInt32()).split(',');
                const encryption_algorithms_server_to_client = pr.readString(pr.readUInt32()).split(',');
                const mac_algorithms_client_to_server = pr.readString(pr.readUInt32()).split(',');
                const mac_algorithms_server_to_client = pr.readString(pr.readUInt32()).split(',');
                const compression_algorithms_client_to_server = pr.readString(pr.readUInt32()).split(',');
                const compression_algorithms_server_to_client = pr.readString(pr.readUInt32()).split(',');
                const languages_client_to_server = pr.readString(pr.readUInt32()).split(',');
                const languages_server_to_client = pr.readString(pr.readUInt32()).split(',');


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
                }
                console.log(nameLists);
                
                const _first_kex_packet_follows = pr.readBoolean();
                
                assert.equal(pr.readUInt32(), 0, "Failed to parse 'KEXINIT' message future extension bool is not '0'");

                console.log("SSH_MSG_KEXINIT");
                


                socket.write(Buffer.from([
                    20,
                    ...getRandomByteBuffer(16), // Cookie
                    ...kexToPayload(),
                    0,
                    ...toUInt32Buffer(0),
                    ...Buffer.from("\r\n"),
                ]))
                if (pr.rest().length == 0) return;
            }

            console.log({ packet_len, padding_len, payload });


            console.log("Something else...");

        },
        open(socket) {
            socket.data = { sessionId: crypto.randomUUID() };
            console.log("open", socket);
        }
    }
});



type Kex = {
    kex_algorithms: string[],
    server_host_key_algorithms: string[],
    encryption_algorithms_client_to_server: string[],
    encryption_algorithms_server_to_client: string[],
    mac_algorithms_client_to_server: string[],
    mac_algorithms_server_to_client: string[],
    compression_algorithms_client_to_server: string[],
    compression_algorithms_server_to_client: string[],
    languages_client_to_server: string[],
    languages_server_to_client: string[],
};

function getServerKex(): Kex {
    return {
        kex_algorithms: ["curve25519-sha256"],
        server_host_key_algorithms: ["ssh-ed25519-cert-v01@openssh.com"],
        encryption_algorithms_client_to_server: ["chacha20-poly1305@openssh.com"],
        encryption_algorithms_server_to_client: ["chacha20-poly1305@openssh.com"],
        mac_algorithms_client_to_server: ["umac-64-etm@openssh.com"],
        mac_algorithms_server_to_client: ["umac-64-etm@openssh.com"],
        compression_algorithms_client_to_server: ["none"],
        compression_algorithms_server_to_client: ["none"],
        languages_client_to_server: [""],
        languages_server_to_client: [""],
    }
}

function kexToPayload() {
    const kex = getServerKex();
    return [
        ...toUInt32Buffer(kex.kex_algorithms.join(',').length),
        ...Buffer.from(kex.kex_algorithms.join(','), "ascii"),
        ...toUInt32Buffer(kex.server_host_key_algorithms.join(',').length),
        ...Buffer.from(kex.server_host_key_algorithms.join(','), "ascii"),
        ...toUInt32Buffer(kex.encryption_algorithms_client_to_server.join(',').length),
        ...Buffer.from(kex.encryption_algorithms_client_to_server.join(','), "ascii"),
        ...toUInt32Buffer(kex.encryption_algorithms_server_to_client.join(',').length),
        ...Buffer.from(kex.encryption_algorithms_server_to_client.join(','), "ascii"),
        ...toUInt32Buffer(kex.mac_algorithms_client_to_server.join(',').length),
        ...Buffer.from(kex.mac_algorithms_client_to_server.join(','), "ascii"),
        ...toUInt32Buffer(kex.mac_algorithms_server_to_client.join(',').length),
        ...Buffer.from(kex.mac_algorithms_server_to_client.join(','), "ascii"),
        ...toUInt32Buffer(kex.compression_algorithms_client_to_server.join(',').length),
        ...Buffer.from(kex.compression_algorithms_client_to_server.join(','), "ascii"),
        ...toUInt32Buffer(kex.compression_algorithms_server_to_client.join(',').length),
        ...Buffer.from(kex.compression_algorithms_server_to_client.join(','), "ascii"),
        ...toUInt32Buffer(kex.languages_client_to_server.join(',').length),
        ...Buffer.from(kex.languages_client_to_server.join(','), "ascii"),
        ...toUInt32Buffer(kex.languages_server_to_client.join(',').length),
        ...Buffer.from(kex.languages_server_to_client.join(','), "ascii"),
    ]
}


function getRandomByteBuffer(length: number) {
    return new Array(length).fill(0).map(() => Math.floor(Math.random() * 255))
}

function toUInt32Buffer(num: number, endian: Endian = Endian.Big) {
    const buf = Buffer.from([0,0,0,0]);
    if (endian == Endian.Big) {
        buf.writeUInt32BE(num);
    } else {
        buf.writeUInt32LE(num);
    }
    return buf;
}

console.log("Running server", );