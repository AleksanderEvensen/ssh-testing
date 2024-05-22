import ssh2 from "ssh2";


const server = new ssh2.Server({
    hostKeys: [],
    debug: (msg) => console.log(`[DEBUG] ${msg}`),
}, (client) => {
    console.log("Client connected");
    client.on("authentication", () => console.log("Client aucthenticated"));
    client.on("close", () => console.log("Closing connection"));
}).listen(8080);