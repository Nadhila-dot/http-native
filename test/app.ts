import { createApp } from "../src/index.js";

let app = createApp();

app.error(async (error, req, res) => {
    await Promise.resolve();
    console.error("Error", error, req, res);
});

app.get("/", (req, res) => {

    res.json({
        ok: true,
        data: req.query,
    });
});



const server = await app.listen({
    port: 8190,
    
    opt: { notify: true}
});

console.log(`http-native listening on ${server.url}`);
