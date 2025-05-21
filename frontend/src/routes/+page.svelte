<script lang="ts">
    import { API_BASE } from '$lib/api';
    import { browser } from '$app/environment';
    import type { PageData } from './$types';

    export let data: PageData;
</script>

<section class="min-h-screen bg-gradient-to-tr from-blue-900 to-purple-900 flex flex-col justify-center items-center text-white text-center px-4">
    <h1 class="text-5xl sm:text-6xl font-bold mb-4 animate-pulse drop-shadow-lg">
        🚀 Welcome to Your SvelteKit App
    </h1>
    <p class="text-lg sm:text-xl mb-6 max-w-xl">
        Powered by <span class="font-semibold">SvelteKit</span> on the front and <span class="font-semibold">Go</span> on the back.
        Serving blazing fast, statically rendered pages — and connecting to real backend APIs.
    </p>
    {#if browser}
        <a href="{API_BASE}/api/health" target="_blank" class="px-6 py-3 rounded-xl bg-white text-blue-900 font-semibold shadow-md hover:scale-105 transition transform">
            Check API Health
        </a>
    {/if}
    <p class="mt-10 text-sm opacity-80">Built at {data.buildDate}</p>
</section>