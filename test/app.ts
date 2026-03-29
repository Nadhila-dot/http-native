import { createApp } from "../src/index.js";

let app = createApp();

const db: any = {
    getUser: async (id: number) => {
        await Promise.resolve();
        return {
            id,
            name: "Alice"
        }
    }
}

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


/**
 * [http-native optimization] bridge-dispatch
 * This route currently runs through bridge dispatch because it depends on runtime request data. 
 */
app.get("/url", async (req, res) => {
    const data = await db.getUser(Math.floor(Math.random() * 1000) + 1);
    res.status(200).json({
        ok: true,
        data: data
    });
});

const server = await app.listen().port(8190).opt({ devComments: true});



console.log(`http-native listening on ${server.url}`);
