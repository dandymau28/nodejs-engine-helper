const express = require("express");
const multer = require("multer");
const axios = require("axios");
const fs = require("fs");
const mysql = require("mysql2/promise");
const crypto = require("crypto");
const { Storage } = require("@google-cloud/storage");

const app = express();
const port = 3000;

app.use(express.json());

const upload = multer({ dest: "uploads/" });

const storage = new Storage({
    keyFilename: process.env.GOOGLE_CLOUD_KEY_FILE || './gcs-credentials.json',
    projectId: process.env.GOOGLE_CLOUD_PROJECT_ID || 'your-project-id'
});

const bucketName = process.env.GCS_BUCKET_NAME || 'your-bucket-name';

const dbConfig = {
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'nodejs_engine'
};

const variantId = {
    "dev": "0198e568-848b-739d-b881-bd7dced93a90",
    "uat": "018b7c35-9f42-7a89-b3e2-1234567890ab",
    "pentest": "0198ca98-5fb5-7efe-b52b-ced740d69165",
    "prod": "0198e568-f04f-7dfa-b5fa-a2a4ab217d32"
}

app.post("/upload", upload.fields([{ name: 'file', maxCount: 1 }, { name: 'bundle_file', maxCount: 1 }]), async (req, res) => {
    try {
        if (!req.files || !req.files.file || !req.files.file[0]) {
            return res.status(400).json({ error: "No file uploaded" });
        }

        if (!req.files.bundle_file || !req.files.bundle_file[0]) {
            return res.status(400).json({ error: "No bundle file uploaded" });
        }

        if (!req.body.app) {
            return res.status(400).json({ error: "No app informed" });
        }

        if (!req.body.device) {
            return res.status(400).json({ error: "No device informed" });
        }

        if (!req.body.env) {
            return res.status(400).json({ error: "No env informed" });
        }

        const fileBuffer = fs.readFileSync(req.files.file[0].path);
        const base64Bundle = fileBuffer.toString("base64");

        const bundleFileBuffer = fs.readFileSync(req.files.bundle_file[0].path);
        const checksumBundleFile = crypto.createHash('sha256').update(bundleFileBuffer).digest('hex');

        let appId = 1; // homepage 1, portfolio 2
        let device = "1"; //iOS 1, android 2
        let env = "018b7c35-9f42-7a89-b3e2-1234567890ab"; // 018b7c35-9f42-7a89-b3e2-1234567890ab UAT, // 0198ca98-5fb5-7efe-b52b-ced740d69165 PENTEST

        if (req.body.app.toLowerCase() == "portfolio") {
            console.log("Portfolio app selected");
            appId = 2; // portfolio
        }

        if (req.body.device.toLowerCase() == "android") {
            console.log("Android device selected");
            device = "2"; // android
        }

        env = variantId[req.body.env.toLowerCase()] || "";
        
        if (!env) {
            return res.status(400).json({ error: "Invalid env value" });
        }

        console.log(`App ID: ${appId}, Device: ${device}, Environment: ${env}`);

        const response = await axios.post(
            "http://localhost:7010/api/v1/ota/create_version",
            {
                username: "test",
                client: "BRIMON",
                request_refnum: "123456789012",
                timestamp: "1234567890123",
                channel_id: "NBMB",
                app_id: appId,
                version_type: "patch",
                device: device,
                variant_id: env,
                bundle: base64Bundle,
                bundle_source_checksum: checksumBundleFile
            }
        );

        fs.unlinkSync(req.files.file[0].path);
        fs.unlinkSync(req.files.bundle_file[0].path);

        res.json({
            success: true,
            message: "File uploaded and processed successfully",
            data: response.data,
        });
    } catch (error) {
        if (req.files && req.files.file && req.files.file[0] && fs.existsSync(req.files.file[0].path)) {
            fs.unlinkSync(req.files.file[0].path);
        }

        if (req.files && req.files.bundle_file && req.files.bundle_file[0] && fs.existsSync(req.files.bundle_file[0].path)) {
            fs.unlinkSync(req.files.bundle_file[0].path);
        }

        console.log("error", error);

        res.status(500).json({
            error: "Failed to process file",
            details: error.message,
        });
    }
});

app.post("/upload-gcs", upload.single("file"), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: "No file uploaded" });
        }

        if (!req.body.filename) {
            return res.status(400).json({ error: "Filename is required" });
        }

        const bucket = storage.bucket(bucketName);
        const fileName = req.body.filename;
        const file = bucket.file(fileName);

        const fileBuffer = fs.readFileSync(req.file.path);

        await file.save(fileBuffer, {
            metadata: {
                contentType: req.file.mimetype,
            },
        });

        fs.unlinkSync(req.file.path);

        const publicUrl = `https://storage.googleapis.com/${bucketName}/${fileName}`;

        res.json({
            success: true,
            message: "File uploaded to GCS successfully",
            data: {
                filename: fileName,
                bucket: bucketName,
                publicUrl: publicUrl,
                size: fileBuffer.length,
                contentType: req.file.mimetype
            }
        });
    } catch (error) {
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }

        console.log("GCS upload error", error);

        res.status(500).json({
            error: "Failed to upload file to GCS",
            details: error.message,
        });
    }
});

app.post("/insert-data", async (req, res) => {
    try {
        const { data } = req.body;
        
        if (!data || typeof data !== 'string') {
            return res.status(400).json({ error: "Data string is required" });
        }

        const dataArray = data.split('|');
        
        if (dataArray.length === 0) {
            return res.status(400).json({ error: "No data found after splitting by pipe" });
        }

        const connection = await mysql.createConnection(dbConfig);
        
        try {
            const insertQuery = 'INSERT INTO data_table (value) VALUES ?';
            const values = dataArray.map(item => [item.trim()]);
            
            const [result] = await connection.execute(insertQuery, [values]);
            
            await connection.end();
            
            res.json({
                success: true,
                message: "Data inserted successfully",
                insertedRows: result.affectedRows,
                data: dataArray
            });
        } catch (dbError) {
            await connection.end();
            throw dbError;
        }
        
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({
            error: "Failed to insert data",
            details: error.message
        });
    }
});

app.post("/generate-checksum", upload.single("file"), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: "No file uploaded" });
        }

        const fileBuffer = fs.readFileSync(req.file.path);
        
        const md5Hash = crypto.createHash('md5').update(fileBuffer).digest('hex');
        const sha1Hash = crypto.createHash('sha1').update(fileBuffer).digest('hex');
        const sha256Hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

        fs.unlinkSync(req.file.path);

        res.json({
            success: true,
            message: "Checksum generated successfully",
            data: {
                filename: req.file.originalname,
                size: fileBuffer.length,
                checksums: {
                    md5: md5Hash,
                    sha1: sha1Hash,
                    sha256: sha256Hash
                }
            }
        });
    } catch (error) {
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }

        console.log("Checksum generation error", error);

        res.status(500).json({
            error: "Failed to generate checksum",
            details: error.message,
        });
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
