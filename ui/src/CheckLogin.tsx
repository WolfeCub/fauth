import { Component, createEffect, createResource, createSignal, Match, onMount, Show, Switch } from 'solid-js';
import axios from "axios";
import { FloatingBox } from './FloatingBox';
import { Login } from './Login';
import { Spinner } from './Spinner';

export const CheckLogin: Component = () => {
    const [verified, { refetch, mutate }] = createResource(async () => {
        try {
            const response = await axios.get("/api/verify", {
                withCredentials: true,
                params: {
                    disable_redirect: true,
                },
            });
            return response.status === 200;
        } catch (e) {
            return false;
        }
    });

    createEffect(() => {
        const urlSearchParams = new URLSearchParams(window.location.search);
        const params = Object.fromEntries(urlSearchParams.entries());
        const redirectUrl = params["redirect"];

        if (verified() && redirectUrl) {
            document.location.href = redirectUrl;
        }
    })

    const refetchMutate = async () => {
        mutate(await refetch());
    };

    return (
        <FloatingBox>
            <Switch fallback={<Login refetch={refetchMutate} />}>
                <Match when={verified()}>
                    <h1>You're logged in</h1>
                </Match>
                <Match when={verified.loading}>
                    <Spinner />
                </Match>
            </Switch>
        </FloatingBox>

    );
};
