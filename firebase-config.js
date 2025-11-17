// firebase-config.js
import admin from 'firebase-admin';

// Lee el valor del Secret de Fly.io
const serviceAccountString = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

if (!serviceAccountString) {
    throw new Error("ERROR: La variable FIREBASE_SERVICE_ACCOUNT_JSON no está definida.");
}

// Lo convierte de texto JSON a un objeto JavaScript
const serviceAccount = JSON.parse(serviceAccountString); 

// Inicializa Firebase con el objeto
const app = admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

// Exporta los servicios
const auth = admin.auth(app);
const db = admin.firestore(app);
const FieldValue = admin.firestore.FieldValue; 

export { auth, db, FieldValue };
