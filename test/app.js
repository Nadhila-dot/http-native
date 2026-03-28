import { createApp } from "../src/index.js";

const app = createApp();

app.error(async (error, req, res) => {
    await Promise.resolve();
    console.error("Error observed in error handler:", error, req, res);
});

app.get("/", (req, res) => {
    res.json({
        ok: true,
    });
});




const server = await app.listen({
    port: 8190
});
console.log(`http-native listening on ${server.url}`);
