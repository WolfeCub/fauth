import { Component, createSignal, Show } from "solid-js";
import { createStore } from "solid-js/store";
import axios from 'axios';

interface Props {
    refetch: () => Promise<void>
}

export const Login: Component<Props> = (props) => {
    const [loginInfo, setLoginInfo] = createStore({
        username: '',
        password: '',
    });

    const [showError, setShowError] = createSignal(false);

    const login = async () => {
        try {
            await axios.post("/api/user/login", loginInfo, {
                withCredentials: true,
            });

            await props.refetch();
        } catch {
            setShowError(true);
        }
    };

    const onSubmit = async (e: SubmitEvent) => {
        e.preventDefault();
        await login();
    }

    const inputStyles = "shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline";

    return (
        <>
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
                        value={loginInfo.username}
                        onInput={(e) => setLoginInfo({ username: e.currentTarget.value })}
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
                        value={loginInfo.password}
                        onInput={(e) => setLoginInfo({ password: e.currentTarget.value })}
                        id="password"
                        type="password"
                        placeholder="Password"
                    />
                </div>
                <button
                    class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded w-full"
                    type="submit"
                >Login</button>
            </form>
            <Show when={showError()}>
                <div class="pt-5 flex justify-center">
                    <span class="text-red-600">Invalid username or password.</span>
                </div>
            </Show>
        </>
    );
}
