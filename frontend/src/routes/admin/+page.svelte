<script lang="ts">
    import {auth} from '$lib/stores/auth';
    import {goto} from '$app/navigation';
    import {onMount} from 'svelte';
    import {ExternalLink, Shield} from 'lucide-svelte';
    import {browser} from "$app/environment";
    import {API_BASE} from "$lib/api";

    onMount(() => {
        if (!$auth.user) {
            goto('/auth?mode=login');
        } else if (!$auth.user.roles.includes('admin')) {
            goto('/');
        }
    });
</script>

<svelte:head>
    <title>Admin Panel</title>
</svelte:head>

{#if $auth.user && $auth.user.roles.includes('admin')}
    <div class="container mx-auto">
        <div class="max-w-6xl mx-auto">
            <div class="flex items-center gap-3 mb-8">
                <Shield size="32" class="text-error"/>
                <h1 class="text-3xl font-bold">Admin Panel</h1>
            </div>

            <div class="flex">
                {#if browser}
                    <a href="{API_BASE}/api/health" target="_blank" class="btn btn-primary">
                        <ExternalLink size="20"/>
                        API Health Check
                    </a>
                {/if}
            </div>
        </div>
    </div>
{/if}