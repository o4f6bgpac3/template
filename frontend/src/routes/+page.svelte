<script lang="ts">
    import {APP_CONFIG} from '$lib/config';
    import {auth} from '$lib/stores/auth';
    import {CheckCircle, DollarSign, User} from 'lucide-svelte';
</script>

<svelte:head>
    <title>{APP_CONFIG.title}</title>
    <meta name="description" content={APP_CONFIG.description}/>
</svelte:head>

{#if $auth.user}
    <div class="container mx-auto">
        <div class="max-w-4xl mx-auto">
            <h1 class="text-4xl font-bold mb-6 text-base-content">
                Welcome Back! 🎉
            </h1>
            <p class="text-lg mb-8 text-base-content/70">
                You're successfully authenticated and ready to explore your dashboard.
            </p>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
                <div class="stat bg-base-100 shadow rounded-lg p-6">
                    <div class="stat-figure text-primary">
                        <CheckCircle size="32"/>
                    </div>
                    <div class="stat-title">Account Status</div>
                    <div class="stat-value text-primary">Active</div>
                    <div class="stat-desc">Fully verified</div>
                </div>

                <div class="stat bg-base-100 shadow rounded-lg p-6">
                    <div class="stat-figure text-secondary">
                        <User size="32"/>
                    </div>
                    <div class="stat-title">User Role</div>
                    <div class="stat-value text-secondary">{$auth.user.roles[0]}</div>
                    <div class="stat-desc">Primary role</div>
                </div>

                <div class="stat bg-base-100 shadow rounded-lg p-6">
                    <div class="stat-figure text-accent">
                        <DollarSign size="32"/>
                    </div>
                    <div class="stat-title">Session</div>
                    <div class="stat-value text-accent">Online</div>
                    <div class="stat-desc">Active session</div>
                </div>
            </div>
        </div>
    </div>
{:else}
    <div class="flex items-center justify-center min-h-full">
        <div class="max-w-2xl mx-auto text-center">
            <h1 class="text-4xl font-bold mb-6 text-base-content">
                Welcome to {APP_CONFIG.title}
            </h1>
            <p class="text-lg mb-8 text-base-content/70">
                Please sign in to access your dashboard and explore all features.
            </p>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                <div class="card bg-base-100 shadow-xl">
                    <div class="card-body">
                        <h2 class="card-title">Existing User?</h2>
                        <p>Sign in to your account to continue where you left off.</p>
                        <div class="card-actions justify-end">
                            <a href="/auth?mode=login" class="btn btn-primary">
                                Sign In
                            </a>
                        </div>
                    </div>
                </div>

                <div class="card bg-base-100 shadow-xl">
                    <div class="card-body">
                        <h2 class="card-title">New Here?</h2>
                        <p>Create an account to get started with our platform.</p>
                        <div class="card-actions justify-end">
                            <a href="/auth?mode=register" class="btn btn-outline">
                                Sign Up
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
{/if}