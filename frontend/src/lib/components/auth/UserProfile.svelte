<script lang="ts">
    import {auth, authService} from '$lib/stores/auth';
    import {toast} from '$lib/stores/toast';
    import {Check, Edit, FileText, Lock, X} from 'lucide-svelte';

    let showChangePassword = $state(false);
    let currentPassword = $state('');
    let newPassword = $state('');
    let confirmPassword = $state('');
    let loading = $state(false);
    let error = $state('');

    async function handleChangePassword() {
        error = '';

        if (!currentPassword || !newPassword || !confirmPassword) {
            error = 'Please fill in all fields';
            return;
        }

        if (newPassword !== confirmPassword) {
            error = 'New passwords do not match';
            return;
        }

        if (newPassword.length < 8) {
            error = 'Password must be at least 8 characters long';
            return;
        }

        loading = true;

        try {
            await authService.changePassword(currentPassword, newPassword);

            toast.success('Password changed successfully!');

            currentPassword = '';
            newPassword = '';
            confirmPassword = '';
            showChangePassword = false;
        } catch (err) {
            const errorMessage = err instanceof Error ? err.message : 'Failed to change password';
            error = errorMessage;
            toast.error(errorMessage);
        } finally {
            loading = false;
        }
    }

    function getRoleColor(role: string): string {
        switch (role.toLowerCase()) {
            case 'admin':
                return 'badge-error';
            case 'moderator':
                return 'badge-warning';
            case 'user':
                return 'badge-primary';
            default:
                return 'badge-ghost';
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

    const passwordErrors = $derived(newPassword ? validatePassword(newPassword) : []);
    const passwordValid = $derived(passwordErrors.length === 0);
</script>

{#if $auth.user}
    <div class="container mx-auto">
        <div class="max-w-4xl mx-auto">
            <h1 class="text-3xl font-bold mb-8">Profile</h1>

            <!-- Account Information -->
            <div class="card bg-base-100 shadow-xl mb-6">
                <div class="card-body">
                    <h3 class="card-title">
                        <FileText size="24"/>
                        Account Information
                    </h3>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label class="label">
                                <span class="label-text font-medium">Username</span>
                            </label>
                            <input
                                    type="text"
                                    class="input input-bordered w-full"
                                    value={$auth.user.username}
                                    readonly
                            />
                        </div>
                        <div>
                            <label class="label">
                                <span class="label-text font-medium">Email</span>
                            </label>
                            <input
                                    type="email"
                                    class="input input-bordered w-full"
                                    value={$auth.user.email}
                                    readonly
                            />
                        </div>
                        <div>
                            <label class="label">
                                <span class="label-text font-medium">User ID</span>
                            </label>
                            <input
                                    type="text"
                                    class="input input-bordered w-full"
                                    value={$auth.user.user_id}
                                    readonly
                            />
                        </div>
                        <div>
                            <label class="label">
                                <span class="label-text font-medium">Roles</span>
                            </label>
                            <div class="flex flex-wrap gap-1">
                                {#each $auth.user.roles as role}
                                    <span class="badge {getRoleColor(role)} badge-sm">
                                        {role}
                                    </span>
                                {/each}
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Change Password Section -->
            <div class="card bg-base-100 shadow-xl">
                <div class="card-body">
                    <h3 class="card-title">
                        <Lock size="24"/>
                        Change Password
                    </h3>

                    {#if !showChangePassword}
                        <p class="text-base-content/70 mb-4">
                            Update your password to keep your account secure.
                        </p>
                        <button
                                class="btn btn-outline btn-sm w-fit"
                                onclick={() => showChangePassword = true}
                        >
                            <Edit size="16"/>
                            Change Password
                        </button>
                    {:else}
                        <form onsubmit={(e) => { e.preventDefault(); handleChangePassword(); }} class="space-y-4">
                            <div class="form-control">
                                <label class="label" for="currentPassword">
                                    <span class="label-text font-medium">Current Password</span>
                                </label>
                                <input
                                        id="currentPassword"
                                        type="password"
                                        placeholder="Enter your current password"
                                        class="input input-bordered w-full focus:input-primary"
                                        bind:value={currentPassword}
                                        disabled={loading}
                                        required
                                />
                            </div>

                            <div class="form-control">
                                <label class="label" for="newPassword">
                                    <span class="label-text font-medium">New Password</span>
                                </label>
                                <input
                                        id="newPassword"
                                        type="password"
                                        placeholder="Enter your new password"
                                        class="input input-bordered w-full focus:input-primary"
                                        class:input-error={newPassword && !passwordValid}
                                        class:input-success={newPassword && passwordValid}
                                        bind:value={newPassword}
                                        disabled={loading}
                                        required
                                />
                                {#if newPassword && passwordErrors.length > 0}
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
                                        class:input-error={confirmPassword && newPassword !== confirmPassword}
                                        class:input-success={confirmPassword && newPassword === confirmPassword}
                                        bind:value={confirmPassword}
                                        disabled={loading}
                                        required
                                />
                                {#if confirmPassword && newPassword !== confirmPassword}
                                    <div class="label">
                                        <span class="label-text-alt text-error">
                                            Passwords do not match
                                        </span>
                                    </div>
                                {/if}
                            </div>

                            {#if error}
                                <div class="alert alert-error">
                                    <X size="20"/>
                                    <span>{error}</span>
                                </div>
                            {/if}

                            <div class="flex gap-2">
                                <button
                                        type="submit"
                                        class="btn btn-primary"
                                        class:loading
                                        disabled={loading || !passwordValid || newPassword !== confirmPassword}
                                >
                                    {#if loading}
                                        <span class="loading loading-spinner"></span>
                                        Updating Password...
                                    {:else}
                                        <Check size="16"/>
                                        Update Password
                                    {/if}
                                </button>
                                <button
                                        type="button"
                                        class="btn btn-ghost"
                                        onclick={() => {
                                        showChangePassword = false;
                                        currentPassword = '';
                                        newPassword = '';
                                        confirmPassword = '';
                                        error = '';
                                    }}
                                        disabled={loading}
                                >
                                    <X size="16"/>
                                    Cancel
                                </button>
                            </div>
                        </form>
                    {/if}
                </div>
            </div>
        </div>
    </div>
{/if}