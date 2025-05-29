<script lang="ts">
    import {auth, authService} from '$lib/stores/auth';
    import {goto} from '$app/navigation';
    import {onMount} from 'svelte';
    import {Palette, Shield} from 'lucide-svelte';
    import ThemeSwitcher from '$lib/components/ThemeSwitcher.svelte';

    let deletePassword = $state('');
    let showDeleteConfirm = $state(false);

    onMount(() => {
        if (!$auth.user) {
            goto('/auth?mode=login');
        }
    });

    async function handleDeleteAccount(event: SubmitEvent) {
        event.preventDefault();

        if (!deletePassword.trim()) return;

        try {
            await authService.deleteAccount(deletePassword);
            showDeleteConfirm = false;
            await goto('/auth?mode=login');
        } catch (error) {
            console.error('Delete account error:', error);
        } finally {
            deletePassword = '';
        }
    }
</script>

<svelte:head>
    <title>Settings</title>
</svelte:head>

{#if $auth.user}
    <div class="container mx-auto">
        <div class="max-w-4xl mx-auto">
            <h1 class="text-3xl font-bold mb-8">Settings</h1>

            <div class="lg:col-span-2 space-y-6">
                <div class="bg-base-200 p-4">
                    <h2 class="card-title mb-4">
                        <Palette size="20"/>
                        Appearance
                    </h2>

                    <div class="form-control">
                        <div class="flex items-center gap-4">
                            <span>Choose your preferred theme:</span>
                            <ThemeSwitcher position="start"/>
                        </div>
                    </div>
                </div>

                <div class="bg-base-200 p-4">
                    <h2 class="card-title mb-4">
                        <Shield size="20"/>
                        Privacy & Security
                    </h2>

                    <div class="flex gap-4">
                        <button class="btn btn-outline" disabled>Enable 2FA</button>
                        <button class="btn btn-outline" disabled>Download Data</button>
                        <button
                                class="btn btn-error btn-outline"
                                onclick={() => showDeleteConfirm = true}
                        >
                            Delete Account
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    {#if showDeleteConfirm}
        <div class="modal modal-open">
            <form class="modal-box" onsubmit={handleDeleteAccount}>
                <h3 class="font-bold text-lg text-error">Delete Account</h3>
                <p class="py-4">
                    This action cannot be undone. All your data will be permanently deleted.
                    Please enter your password to confirm.
                </p>

                <div class="form-control w-full">
                    <input
                            type="text"
                            name="username"
                            value={$auth.user.username}
                            autocomplete="username"
                            style="display: none;"
                            readonly
                    />
                    <input
                            type="password"
                            name="password"
                            autocomplete="current-password"
                            placeholder="Enter your password"
                            class="input input-bordered w-full"
                            bind:value={deletePassword}
                            disabled={$auth.loading}
                    />
                </div>

                {#if $auth.error}
                    <div class="alert alert-error mt-4">
                        <span>{$auth.error}</span>
                    </div>
                {/if}

                <div class="modal-action">
                    <button
                            type="button"
                            class="btn"
                            onclick={() => {
                            showDeleteConfirm = false;
                            deletePassword = '';
                            authService.clearError();
                        }}
                            disabled={$auth.loading}
                    >
                        Cancel
                    </button>
                    <button
                            type="submit"
                            class="btn btn-error"
                            disabled={!deletePassword.trim() || $auth.loading}
                    >
                        {$auth.loading ? 'Deleting...' : 'Delete Account'}
                    </button>
                </div>
            </form>
        </div>
    {/if}
{/if}