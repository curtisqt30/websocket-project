import { initializeApp } from "https://www.gstatic.com/firebasejs/11.7.1/firebase-app.js";
import { getStorage, ref, uploadBytes, getDownloadURL } from "https://www.gstatic.com/firebasejs/11.7.1/firebase-storage.js";

const firebaseConfig = {
  apiKey: "AIzaSyDeb-bHUIm1vchbyuG_6S4MWYBlZYmMwIA",
  authDomain: "curtisconnect-a1630.firebaseapp.com",
  projectId: "curtisconnect-a1630",
  storageBucket: "curtisconnect-a1630.appspot.com",
  messagingSenderId: "699870738851",
  appId: "1:699870738851:web:5ee9945895f1d723540216",
  measurementId: "G-CYHF4J5B49"
};

const app = initializeApp(firebaseConfig);
const storage = getStorage(app);

window.firebaseStorage = storage;
window.firebaseRef = ref;
window.firebaseUploadBytes = uploadBytes;
window.firebaseGetDownloadURL = getDownloadURL;
