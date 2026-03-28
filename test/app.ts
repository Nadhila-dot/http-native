import { createApp } from "../src/index.js";

let app = createApp();

app.error(async (error, req, res) => {
    await Promise.resolve();
    console.error("Error", error, req, res);
});

const db = {
    async getUser(id: number) {
        return {
        id,
        name: "Ada Lovelace",
        role: "admin",
        };
    },
};

app.get("/", async (req, res) => {
    
    const data = await db.getUser(233242)
    res.json({
        ok: true,
        data: req.query,
        data_2: data,
    });
});

app.get("/stable", async (req, res) => {
    
    res.json({
       ok: true
    });
});

const server = await app.listen({
    port: 8190,
    opt: { notify: true}
});

console.log(`http-native listening on ${server.url}`);
