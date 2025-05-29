<script lang="ts">
    import {onMount} from 'svelte';
    import {auth} from '$lib/stores/auth';
    import {goto} from '$app/navigation';
    import Auth from '$lib/components/auth/Auth.svelte';

    onMount(() => {
        if ($auth.user) {
            goto('/');
        }
    });
</script>

<div class="flex items-center justify-center min-h-full">
    <div class="w-full">
        <Auth/>
    </div>
</div>