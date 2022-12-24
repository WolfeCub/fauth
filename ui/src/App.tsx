import { Route, Router, Routes } from "@solidjs/router";
import { Admin } from "./Admin";
import { CheckLogin } from "./CheckLogin";

export const App = () => {
    return (
        <Router>
            <Routes>
                <Route path="/" component={CheckLogin} />
                <Route path="/admin" component={Admin} />
            </Routes>
        </Router>
    );
};
