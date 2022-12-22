<script lang="ts">
    import axios from "axios";

    import { onMount } from "svelte";
    import FloatingBox from "./FloatingBox.svelte";
    import Login from "./Login.svelte";

    let is_logged_in = false;

    onMount(async () => {
        await axios.get("/api/verify", {
            withCredentials: true,
            params: {
                disable_redirect: true,
            },
        });
        is_logged_in = true;
    });
</script>

{#if is_logged_in}
    <FloatingBox>
        <h1>You're logged in</h1>
    </FloatingBox>
{:else}
    <Login />
{/if}
