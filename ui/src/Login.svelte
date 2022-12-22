<script lang="ts">
    import axios from "axios";
    import FloatingBox from "./FloatingBox.svelte";

    let username = "";
    let password = "";

    const login = async () => {
        await axios.post(
            "/api/user/login",
            {
                username: username,
                password: password,
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
</script>

<FloatingBox>
    <div class="mb-4">
        <label
            class="block text-gray-700 text-sm font-bold mb-2"
            for="username"
        >
            Username
        </label>
        <input
            class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
            bind:value={username}
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
            class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
            bind:value={password}
            id="password"
            type="password"
            placeholder="Password"
        />
    </div>
    <button
        class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
        on:click={login}>Login</button
    >
</FloatingBox>
