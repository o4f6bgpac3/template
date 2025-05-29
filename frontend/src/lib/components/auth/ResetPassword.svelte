<script lang="ts">
    import {authService} from '$lib/stores/auth';
    import {Lock} from 'lucide-svelte';

    const {token = '', onswitchmode} = $props<{ token?: string; onswitchmode?: (mode: string) => void }>();

    let password = $state('');
    let confirmPassword = $state('');
    let loading = $state(false);
    let error = $state('');
    let success = $state('');

    async function handleSubmit() {
        error = '';
        success = '';

        if (!password.trim() || !confirmPassword.trim()) {
            error = 'Please fill in all fields';
            return;
        }

        if (password !== confirmPassword) {
            error = 'Passwords do not match';
            return;
        }

        if (password.length < 8) {
            error = 'Password must be at least 8 characters long';
            return;
        }

        loading = true;

        try {
            const result = await authService.resetPassword(token, password);
            success = result.message || 'Password has been reset successfully.';
            loading = false;

            setTimeout(() => {
                onswitchmode?.('login');
            }, 2000);
        } catch (err) {
            error = err instanceof Error ? err.message : 'Failed to reset password';
            loading = false;
        }
    }

    function validatePassword(password: string): string[] {
        const errors = [];
        if (password.length < 8) errors.push('At least 8 characters');
        if (!/[A-Z]/.test(password)) errors.push('One uppercase letter');
        if (!/[a-z]/.test(password)) errors.push('One lowercase letter');
        if (!/[0-9]/.test(password)) errors.push('One number');
        if (!/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)) errors.push('One special character');
        return errors;
    }

    const passwordErrors = $derived(password ? validatePassword(password) : []);
    const passwordValid = $derived(passwordErrors.length === 0);
</script>

<div class="card bg-base-100 shadow-xl max-w-md mx-auto">
    <div class="card-body">
        <h2 class="card-title text-2xl font-bold text-center justify-center mb-6">
            <Lock class="text-3xl mr-2" size="32"/>
            Set New Password
        </h2>

        <p class="text-center text-base-content/70 mb-6">
            Enter your new password below.
        </p>

        <form onsubmit={(e) => { e.preventDefault(); handleSubmit(); }} class="space-y-4">
            <div class="form-control">
                <label class="label" for="password">
                    <span class="label-text font-medium">New Password</span>
                </label>
                <input
                        id="password"
                        type="password"
                        placeholder="Enter your new password"
                        class="input input-bordered w-full focus:input-primary"
                        class:input-error={password && !passwordValid}
                        class:input-success={password && passwordValid}
                        bind:value={password}
                        disabled={loading}
                        required
                />
                {#if password && passwordErrors.length > 0}
                    <div class="label">
                        <span class="label-text-alt text-error">
                            Missing: {passwordErrors.join(', ')}
                        </span>
                    </div>
                {/if}
            </div>

            <div class="form-control">
                <label class="label" for="confirmPassword">
                    <span class="label-text font-medium">Confirm New Password</span>
                </label>
                <input
                        id="confirmPassword"
                        type="password"
                        placeholder="Confirm your new password"
                        class="input input-bordered w-full focus:input-primary"
                        class:input-error={confirmPassword && password !== confirmPassword}
                        class:input-success={confirmPassword && password === confirmPassword}
                        bind:value={confirmPassword}
                        disabled={loading}
                        required
                />
                {#if confirmPassword && password !== confirmPassword}
                    <div class="label">
                        <span class="label-text-alt text-error">
                            Passwords do not match
                        </span>
                    </div>
                {/if}
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
                        disabled={loading || !passwordValid || password !== confirmPassword}
                >
                    {#if loading}
                        <span class="loading loading-spinner"></span>
                        Resetting Password...
                    {:else}
                        Reset Password
                    {/if}
                </button>
            </div>
        </form>

        {#if !success}
            <div class="divider">OR</div>

            <div class="text-center">
                <div class="text-sm">
                    Remember your password?
                    <button
                            class="btn btn-ghost btn-sm text-primary"
                            onclick={() => onswitchmode?.('login')}
                    >
                        Sign In
                    </button>
                </div>
            </div>
        {/if}
    </div>
</div>