import React from "react";
import ReactDOM from "react-dom/client";
import './index.css'
import App from './App.tsx'

const root = document.getElementById("root")!;

ReactDOM.createRoot(root).render(
    import.meta.env.DEV ? (
        <App />
    ) : (
        <React.StrictMode>
            <App />
        </React.StrictMode>
    )
);