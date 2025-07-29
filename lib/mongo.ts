import {MongoClient} from "mongodb";

const uri = process.env.MONGODB_URI;
if (!uri) {
    throw new Error("Connection string not found");
}
const options = {};

let client;
let clientPromise: Promise<MongoClient>;

if (!process.env.MONGODB_URI){
    throw new Error("Connection string not found");
}

declare global {
    var _mongoClientPromise: Promise<MongoClient> | undefined;
}

if (!global._mongoClientPromise){
    client = new MongoClient(uri, options);
    global._mongoClientPromise = client.connect();
}

clientPromise = global._mongoClientPromise;

export default clientPromise;