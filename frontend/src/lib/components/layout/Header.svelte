<script lang="ts">
    import {auth, authService} from '$lib/stores/auth';
    import {APP_CONFIG} from '$lib/config';
    import {LogIn, LogOut, Settings, User, UserCheck, UserPlus} from 'lucide-svelte';
    import ThemeSwitcher from '$lib/components/ThemeSwitcher.svelte';
    import {goto} from '$app/navigation';
</script>

<header class="navbar bg-base-200 px-6">
    <div class="navbar-start">
        <a href="/" class="text-xl font-bold hover:text-primary hover:scale-105 transition-all duration-200">
            {APP_CONFIG.title}
        </a>
    </div>

    <div class="navbar-center">
        <!-- Space for breadcrumbs or page title if needed -->
    </div>

    <div class="navbar-end flex items-center gap-4">
        <ThemeSwitcher position="end"/>

        <div class="dropdown dropdown-end dropdown-hover">
            <div tabindex="-1" role="button" class="btn btn-lg btn-ghost btn-circle avatar border border-primary">
                <User/>
            </div>
            {#if $auth.user}
                <ul tabindex="-1" class="z-[1] p-2 shadow-lg border border-secondary menu dropdown-content bg-base-200 rounded-box w-52">
                    <li class="menu-title">
                        <span class="text-sm font-medium">Signed in as {$auth.user.username}</span>
                    </li>
                    <li><a href="/profile" class="text-sm py-2">
                        <UserCheck size="16"/>
                        Profile
                    </a></li>
                    <li><a href="/settings" class="text-sm py-2">
                        <Settings size="16"/>
                        Settings
                    </a></li>
                    <div class="divider my-0"></div>
                    <li>
                        <button onclick={() => authService.logout()} class="text-sm py-2">
                            <LogOut size="16"/>
                            Sign Out
                        </button>
                    </li>
                </ul>
            {:else}
                <ul tabindex="-1" class="z-[1] p-2 shadow-lg border border-secondary menu dropdown-content bg-base-200 rounded-box w-52">
                    <li>
                        <button onclick={() => goto('/auth?mode=login')} class="text-sm py-2">
                            <LogIn size="16"/>
                            Sign In
                        </button>
                    </li>
                    <li>
                        <button onclick={() => goto('/auth?mode=register')} class="text-sm py-2">
                            <UserPlus size="16"/>
                            Sign Up
                        </button>
                    </li>
                </ul>
            {/if}
        </div>
    </div>
</header>