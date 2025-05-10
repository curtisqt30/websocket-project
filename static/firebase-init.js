import { initializeApp } from "https://cdn.jsdelivr.net/npm/firebase@11.7.1/app/dist/index.esm.js";
import { getStorage, ref, uploadBytes, getDownloadURL } from "https://cdn.jsdelivr.net/npm/firebase@11.7.1/storage/dist/index.esm.js";

const firebaseConfig = {
  apiKey: "AIzaSyDeb-bHUIm1vchbyuG_6S4MWYBlZYmMwIA",
  authDomain: "curtisconnect-a1630.firebaseapp.com",
  projectId: "curtisconnect-a1630",
  storageBucket: "curtisconnect-a1630.firebasestorage.app",
  messagingSenderId: "699870738851",
  appId: "1:699870738851:web:5ee9945895f1d723540216",
  measurementId: "G-CYHF4J5B49"
};

const app = initializeApp(firebaseConfig);
const storage = getStorage(app);
window.firebaseStorage = storage;
