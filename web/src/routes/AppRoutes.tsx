import { Routes, Route } from "react-router-dom";
import PairPage from "../pages/Pair";
import Home from "../pages/Home";


export default function AppRoutes() {
    return (
        <Routes>

            <Route path="/" element={<Home />} />
            <Route path="/pair" element={<PairPage />} />

        </Routes>
    );
}