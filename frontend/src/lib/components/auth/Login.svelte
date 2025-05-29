<script lang="ts">
    import {authService} from '$lib/stores/auth';
    import {Lock} from 'lucide-svelte';

    const {onswitchmode, onsuccess} = $props();

    let emailOrUsername = $state('');
    let password = $state('');
    let loading = $state(false);
    let error = $state('');

    async function handleSubmit() {
        if (!emailOrUsername.trim() || !password.trim()) {
            error = 'Please fill in all fields';
            return;
        }

        loading = true;
        error = '';

        const success = await authService.login(emailOrUsername.trim(), password);

        if (success) {
            onsuccess?.();
        } else {
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
            <Lock class="text-3xl mr-2" size="32"/>
            Welcome Back
        </h2>

        <form onsubmit={(e) => { e.preventDefault(); handleSubmit(); }} class="space-y-4">
            <div class="form-control">
                <label class="label" for="emailOrUsername">
                    <span class="label-text font-medium">Email or Username</span>
                </label>
                <input
                        id="emailOrUsername"
                        type="text"
                        placeholder="Enter your email or username"
                        class="input input-bordered w-full focus:input-primary"
                        bind:value={emailOrUsername}
                        onkeydown={handleKeydown}
                        disabled={loading}
                        required
                />
            </div>

            <div class="form-control">
                <label class="label" for="password">
                    <span class="label-text font-medium">Password</span>
                </label>
                <input
                        id="password"
                        type="password"
                        placeholder="Enter your password"
                        class="input input-bordered w-full focus:input-primary"
                        bind:value={password}
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

            <div class="form-control mt-6">
                <button
                        type="submit"
                        class="btn btn-primary w-full"
                        class:loading
                        disabled={loading || !emailOrUsername.trim() || !password.trim()}
                >
                    {#if loading}
                        <span class="loading loading-spinner"></span>
                        Signing In...
                    {:else}
                        Sign In
                    {/if}
                </button>
            </div>
        </form>

        <div class="divider">OR</div>

        <div class="text-center space-y-2">
            <button
                    class="btn btn-ghost btn-sm"
                    onclick={() => onswitchmode?.('forgot')}
            >
                Forgot your password?
            </button>

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