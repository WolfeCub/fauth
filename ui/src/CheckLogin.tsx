import { Component, createResource, createSignal, onMount, Show } from 'solid-js';
import axios from "axios";
import { FloatingBox } from './FloatingBox';
import { Login } from './Login';

export const CheckLogin: Component = () => {
    const [verify] = createResource(async () =>
        await axios.get("/api/verify", {
            withCredentials: true,
            params: {
                disable_redirect: true,
            },
        })
    );

    return (
        <Show when={(verify()?.status ?? -1) == 200}
            fallback={<Login />}
        >
            <FloatingBox>
                <h1>You're logged in</h1>
            </FloatingBox>
        </Show>
    );
};
