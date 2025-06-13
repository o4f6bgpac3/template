<script lang="ts">
    import { onMount } from 'svelte';
    import { Shield, AlertTriangle, CheckCircle, RotateCcw } from 'lucide-svelte';
    import { getCSRFToken, clearCSRFToken, preloadCSRFToken } from '$lib/csrf';
    import { toast } from '$lib/stores/toast';

    let status: 'loading' | 'ready' | 'error' | 'refreshing' = 'loading';
    let error: string | null = null;
    let tokenAvailable = false;

    // Check CSRF token status on mount
    onMount(async () => {
        await checkCSRFStatus();
    });

    async function checkCSRFStatus() {
        status = 'loading';
        error = null;

        try {
            await getCSRFToken();
            status = 'ready';
            tokenAvailable = true;
        } catch (e) {
            status = 'error';
            error = e instanceof Error ? e.message : 'CSRF token unavailable';
            tokenAvailable = false;
        }
    }

    async function refreshToken() {
        status = 'refreshing';
        clearCSRFToken();

        try {
            await preloadCSRFToken();
            status = 'ready';
            tokenAvailable = true;
            toast.success('Security token refreshed successfully', 3000);
        } catch (e) {
            status = 'error';
            error = e instanceof Error ? e.message : 'Failed to refresh token';
            tokenAvailable = false;
            toast.error('Failed to refresh security token', 5000);
        }
    }

    function getStatusColor() {
        switch (status) {
            case 'ready': return 'text-success';
            case 'error': return 'text-error';
            case 'loading':
            case 'refreshing': return 'text-warning';
            default: return 'text-gray-500';
        }
    }

    function getStatusIcon() {
        switch (status) {
            case 'ready': return CheckCircle;
            case 'error': return AlertTriangle;
            case 'loading':
            case 'refreshing': return Shield;
            default: return Shield;
        }
    }

    function getStatusText() {
        switch (status) {
            case 'ready': return 'Security token ready';
            case 'error': return 'Security token error';
            case 'loading': return 'Loading security token...';
            case 'refreshing': return 'Refreshing security token...';
            default: return 'Unknown status';
        }
    }
</script>

<!-- Only show if there's an issue that needs user attention -->
{#if status === 'error' || status === 'refreshing'}
    <div class="alert alert-{status === 'error' ? 'error' : 'warning'} shadow-lg mb-4">
        <svelte:component 
            this={getStatusIcon()} 
            class="h-6 w-6"
        />
        <div class="flex-1">
            <h3 class="font-bold">{getStatusText()}</h3>
            {#if error}
                <div class="text-xs opacity-75">{error}</div>
            {/if}
        </div>
        
        {#if status === 'error'}
            <button 
                class="btn btn-sm btn-outline" 
                onclick={refreshToken}
                disabled={status !== 'error'}
            >
                <RotateCcw class="h-4 w-4 mr-1" />
                Refresh Token
            </button>
        {/if}
    </div>
{/if}

<!-- Development mode indicator (only visible in dev) -->
{#if import.meta.env.DEV}
    <div class="fixed bottom-2 left-2 z-50">
        <div class="tooltip tooltip-right" data-tip={getStatusText()}>
            <div class="badge badge-sm gap-1 {getStatusColor()}">
                <svelte:component 
                    this={getStatusIcon()} 
                    class="h-3 w-3"
                />
                CSRF
            </div>
        </div>
    </div>
{/if}