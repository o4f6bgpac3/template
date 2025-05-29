<script lang="ts">
    import { toast } from '$lib/stores/toast';
    import { Check, X, AlertTriangle, Info } from 'lucide-svelte';
    import { fly } from 'svelte/transition';

    // Debug: Log when toasts change
    $effect(() => {
        console.log('Current toasts:', $toast);
    });

    function getIcon(type: string) {
        switch (type) {
            case 'success': return Check;
            case 'error': return X;
            case 'warning': return AlertTriangle;
            case 'info': return Info;
            default: return Info;
        }
    }

    function getAlertClass(type: string) {
        switch (type) {
            case 'success': return 'alert-success';
            case 'error': return 'alert-error';
            case 'warning': return 'alert-warning';
            case 'info': return 'alert-info';
            default: return 'alert-info';
        }
    }
</script>

<div class="toast toast-bottom toast-end z-50 fixed bottom-4 right-4">
    {#each $toast as toastItem (toastItem.id)}
        <div
                class="alert {getAlertClass(toastItem.type)} shadow-lg min-w-64"
                transition:fly={{ x: 300, duration: 300 }}
                style="z-index: 9999;"
        >
            <svelte:component this={getIcon(toastItem.type)} size="20" />
            <span>{toastItem.message}</span>
            <button
                    class="btn btn-ghost btn-sm btn-circle"
                    onclick={() => toast.remove(toastItem.id)}
            >
                <X size="16" />
            </button>
        </div>
    {/each}
</div>