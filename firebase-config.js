// firebase-config.js
import admin from 'firebase-admin';

// ⚠️ NECESARIO: Leemos el JSON de la variable de entorno y lo parseamos
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);

// Inicializar la aplicación de Firebase Admin
const app = admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  // Opcional: Si quieres conectarte a Realtime Database, añade:
  // databaseURL: "https://TU_DATABASE_ID.firebaseio.com"
});

// Obtener los servicios
const auth = admin.auth(app);
const db = admin.firestore(app);
const FieldValue = admin.firestore.FieldValue; // Para actualizaciones atómicas

export { auth, db, FieldValue };
