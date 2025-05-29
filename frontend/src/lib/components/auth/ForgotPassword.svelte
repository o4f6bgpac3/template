<script lang="ts">
    import {authService} from '$lib/stores/auth';
    import {Key} from 'lucide-svelte';

    const {onswitchmode} = $props();

    let email = $state('');
    let loading = $state(false);
    let error = $state('');
    let success = $state('');

    async function handleSubmit() {
        if (!email.trim()) {
            error = 'Please enter your email address';
            return;
        }

        loading = true;
        error = '';
        success = '';

        try {
            const result = await authService.forgotPassword(email.trim());
            success = result.message || 'If the email exists, a password reset link has been sent.';
            loading = false;
        } catch (err) {
            error = err instanceof Error ? err.message : 'Failed to send reset email';
            loading = false;
        }
    }

    function handleKeydown(event: KeyboardEvent) {
        if (event.key === 'Enter') {
            handleSubmit();
        }
    }
</script>

<div class="card bg-base-100 shadow-xl max-w-md mx-auto">
    <div class="card-body">
        <h2 class="card-title text-2xl font-bold text-center justify-center mb-6">
            <Key class="text-3xl mr-2" size="32"/>
            Reset Password
        </h2>

        <p class="text-center text-base-content/70 mb-6">
            Enter your email address and we'll send you a link to reset your password.
        </p>

        <form onsubmit={(e) => { e.preventDefault(); handleSubmit(); }} class="space-y-4">
            <div class="form-control">
                <label class="label" for="email">
                    <span class="label-text font-medium">Email Address</span>
                </label>
                <input
                        id="email"
                        type="email"
                        placeholder="Enter your email address"
                        class="input input-bordered w-full focus:input-primary"
                        bind:value={email}
                        onkeydown={handleKeydown}
                        disabled={loading}
                        required
                />
            </div>

            {#if error}
                <div class="alert alert-error">
                    <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    <span>{error}</span>
                </div>
            {/if}

            {#if success}
                <div class="alert alert-success">
                    <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    <span>{success}</span>
                </div>
            {/if}

            <div class="form-control mt-6">
                <button
                        type="submit"
                        class="btn btn-primary w-full"
                        class:loading
                        disabled={loading || !email.trim()}
                >
                    {#if loading}
                        <span class="loading loading-spinner"></span>
                        Sending Reset Link...
                    {:else}
                        Send Reset Link
                    {/if}
                </button>
            </div>
        </form>

        <div class="divider">OR</div>

        <div class="text-center space-y-2">
            <div class="text-sm">
                Remember your password?
                <button
                        class="btn btn-ghost btn-sm text-primary"
                        onclick={() => onswitchmode?.('login')}
                >
                    Sign In
                </button>
            </div>

            <div class="text-sm">
                Don't have an account?
                <button
                        class="btn btn-ghost btn-sm text-primary"
                        onclick={() => onswitchmode?.('register')}
                >
                    Sign Up
                </button>
            </div>
        </div>
    </div>
</div>