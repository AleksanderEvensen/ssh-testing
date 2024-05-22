export const td = new TextDecoder();


export enum Endian {
    Little,
    Big,
}

export class BufferReader {

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

export type Kex = {
    kex_algorithms: string[];
    server_host_key_algorithms: string[];
    encryption_algorithms_client_to_server: string[];
    encryption_algorithms_server_to_client: string[];
    mac_algorithms_client_to_server: string[];
    mac_algorithms_server_to_client: string[];
    compression_algorithms_client_to_server: string[];
    compression_algorithms_server_to_client: string[];
    languages_client_to_server: string[];
    languages_server_to_client: string[];
};


export function kexToPayload(kex: Kex) {
    return [
        ...toUInt32Buffer(kex.kex_algorithms.join(",").length),
        ...Buffer.from(kex.kex_algorithms.join(","), "ascii"),
        ...toUInt32Buffer(kex.server_host_key_algorithms.join(",").length),
        ...Buffer.from(kex.server_host_key_algorithms.join(","), "ascii"),
        ...toUInt32Buffer(
            kex.encryption_algorithms_client_to_server.join(",").length
        ),
        ...Buffer.from(
            kex.encryption_algorithms_client_to_server.join(","),
            "ascii"
        ),
        ...toUInt32Buffer(
            kex.encryption_algorithms_server_to_client.join(",").length
        ),
        ...Buffer.from(
            kex.encryption_algorithms_server_to_client.join(","),
            "ascii"
        ),
        ...toUInt32Buffer(kex.mac_algorithms_client_to_server.join(",").length),
        ...Buffer.from(kex.mac_algorithms_client_to_server.join(","), "ascii"),
        ...toUInt32Buffer(kex.mac_algorithms_server_to_client.join(",").length),
        ...Buffer.from(kex.mac_algorithms_server_to_client.join(","), "ascii"),
        ...toUInt32Buffer(
            kex.compression_algorithms_client_to_server.join(",").length
        ),
        ...Buffer.from(
            kex.compression_algorithms_client_to_server.join(","),
            "ascii"
        ),
        ...toUInt32Buffer(
            kex.compression_algorithms_server_to_client.join(",").length
        ),
        ...Buffer.from(
            kex.compression_algorithms_server_to_client.join(","),
            "ascii"
        ),
        ...toUInt32Buffer(kex.languages_client_to_server.join(",").length),
        ...Buffer.from(kex.languages_client_to_server.join(","), "ascii"),
        ...toUInt32Buffer(kex.languages_server_to_client.join(",").length),
        ...Buffer.from(kex.languages_server_to_client.join(","), "ascii"),
    ];
}

export function getRandomByteBuffer(length: number) {
    return new Array(length).fill(0).map(() => Math.floor(Math.random() * 255));
}

export function toUInt32Buffer(num: number, endian: Endian = Endian.Big) {
    const buf = Buffer.from([0, 0, 0, 0]);
    if (endian == Endian.Big) {
        buf.writeUInt32BE(num);
    } else {
        buf.writeUInt32LE(num);
    }
    return buf;
}