<script lang="ts">
    import {auth} from '$lib/stores/auth';
    import {goto} from '$app/navigation';
    import {onMount} from 'svelte';
    import UserProfile from '$lib/components/auth/UserProfile.svelte';

    onMount(() => {
        if (!$auth.user) {
            goto('/auth?mode=login');
        }
    });
</script>

<svelte:head>
    <title>Profile</title>
</svelte:head>

{#if $auth.user}
    <UserProfile/>
{/if}