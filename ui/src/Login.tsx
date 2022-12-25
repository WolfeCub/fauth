import { Component, createSignal } from "solid-js";
import { createStore } from "solid-js/store";
import axios from 'axios';
import { FloatingBox } from "./FloatingBox";

interface Props {
    refetch: () => Promise<void>
}

export const Login: Component<Props> = (props) => {
    const [state, setState] = createStore({
        username: '',
        password: '',
    });

    const login = async () => {
        await axios.post("/api/user/login", state, {
            withCredentials: true,
        });

        await props.refetch();
    };

    const onSubmit = async (e: SubmitEvent) => {
        e.preventDefault();
        await login();
    }

    const inputStyles = "shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline";

    return (
        <form onSubmit={onSubmit}>
            <div class="mb-4">
                <label
                    class="block text-gray-700 text-sm font-bold mb-2"
                    for="username"
                >
                    Username
                </label>
                <input
                    class={inputStyles}
                    value={state.username}
                    onInput={(e) => setState({ username: e.currentTarget.value })}
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
                    value={state.password}
                    onInput={(e) => setState({ password: e.currentTarget.value })}
                    id="password"
                    type="password"
                    placeholder="Password"
                />
            </div>
            <button
                class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
                type="submit"
            >Login</button>
        </form>
    );
}
