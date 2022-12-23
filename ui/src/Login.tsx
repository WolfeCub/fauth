import { Component, createSignal } from "solid-js";
import axios from 'axios';
import { FloatingBox } from "./FloatingBox";

export const Login: Component = () => {
    const [username, setUsername] = createSignal('');
    const [password, setPassword] = createSignal('');

    const login = async () => {
        await axios.post(
            "/api/user/login",
            {
                username: username(),
                password: password(),
            },
            {
                withCredentials: true,
            }
        );

        const urlSearchParams = new URLSearchParams(window.location.search);
        const params = Object.fromEntries(urlSearchParams.entries());
        const redirectUrl = params["redirect"];

        if (redirectUrl) document.location.href = redirectUrl;
    };

    const inputStyles = "shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline";

    return (
        <FloatingBox>
            <div class="mb-4">
                <label
                    class="block text-gray-700 text-sm font-bold mb-2"
                    for="username"
                >
                    Username
                </label>
                <input
                    class={inputStyles}
                    value={username()}
                    onInput={(e) => setUsername(e.currentTarget.value)}
                    id="username"
                    type="text"
                    placeholder="Username"
                />
            </div>
            <div class="mb-4">
                <label
                    class="block text-gray-700 text-sm font-bold mb-2"
                    for="password"
                >
                    Password
                </label>
                <input
                    class={inputStyles}
                    value={password()}
                    onInput={(e) => setPassword(e.currentTarget.value)}
                    id="password"
                    type="password"
                    placeholder="Password"
                />
            </div>
            <button
                class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
                onClick={login}>Login</button
            >
        </FloatingBox>
    );
}
