<script lang="ts">
    import '../app.css';
    import {onMount} from 'svelte';
    import {browser} from '$app/environment';
    import {themeChange} from 'theme-change';
    import Header from '$lib/components/layout/Header.svelte';
    import Sidebar from '$lib/components/layout/Sidebar.svelte';
    import Footer from '$lib/components/layout/Footer.svelte';
    import Toast from "$lib/components/Toast.svelte";
    import CSRFStatus from '$lib/components/CSRFStatus.svelte';

    let {children} = $props();

    function applyTheme(theme: string) {
        if (browser) {
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('theme', theme);
        }
    }

    onMount(() => {
        if (browser) {
            themeChange(false);
            const saved = localStorage.getItem('theme') ?? 'light';
            applyTheme(saved);
        }
    });
</script>

<div class="h-screen flex flex-col bg-base-100">
    <div class="flex-none">
        <Header/>
    </div>

    <div class="flex-1 flex min-h-0">
        <div class="flex-none w-64 bg-base-200">
            <Sidebar/>
        </div>

        <main class="flex-1 overflow-y-auto m-8">
            <CSRFStatus/>
            <Toast/>
            {@render children()}
        </main>
    </div>

    <div class="flex-none">
        <Footer/>
    </div>
</div>