<script lang="ts">
    import {onMount} from 'svelte';
    import {browser} from '$app/environment';
    import {themeChange} from 'theme-change';
    import {Palette} from 'lucide-svelte';

    interface Props {
        position?: 'start' | 'end' | 'top' | 'bottom' | 'left' | 'right';
    }

    let {position = 'start'}: Props = $props();

    const themes = [
        'light', 'dark', 'cupcake', 'bumblebee', 'emerald', 'corporate',
        'synthwave', 'retro', 'cyberpunk', 'valentine', 'halloween',
        'garden', 'forest', 'aqua', 'lofi', 'pastel', 'fantasy',
        'wireframe', 'black', 'luxury', 'dracula', 'cmyk', 'autumn',
        'business', 'acid', 'lemonade', 'night', 'coffee', 'winter'
    ];

    let currentTheme = $state('light');

    onMount(() => {
        if (browser) {
            themeChange(false);
            const saved = localStorage.getItem('theme') ?? 'light';
            applyTheme(saved);
        }
    });

    function applyTheme(theme: string) {
        currentTheme = theme;
        if (browser) {
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('theme', theme);
        }
    }

    function getThemeEmoji(theme: string): string {
        const map: Record<string, string> = {
            light: '☀️', dark: '🌙', cupcake: '🧁', bumblebee: '🐝',
            emerald: '💎', corporate: '🏢', synthwave: '🌇', retro: '📺',
            cyberpunk: '🤖', valentine: '💝', halloween: '🎃', garden: '🌸',
            forest: '🌲', aqua: '🌊', lofi: '🎧', pastel: '🎨', fantasy: '🦄',
            wireframe: '📐', black: '⚫', luxury: '👑', dracula: '🧛',
            cmyk: '🖨️', autumn: '🍂', business: '💼', acid: '🧪',
            lemonade: '🍋', night: '🌃', coffee: '☕', winter: '❄️'
        };
        return map[theme] ?? '🎨';
    }

    const positionClass = $derived(`dropdown-${position}`);
</script>

<div class="dropdown {positionClass} dropdown-hover">
    <button tabindex="-1" class="btn btn-ghost btn-circle" aria-label="Change Theme">
        <Palette size="20"/>
    </button>

    <ul tabindex="-1" class="dropdown-content z-[1] menu p-2 shadow-2xl bg-base-100 rounded-box w-96">
        <li class="menu-title"><span>Choose Theme</span></li>

        <div class="grid grid-cols-3 gap-1 max-h-none">
            {#each themes as theme}
                <li>
                    <button
                            class="justify-between text-xs p-2 h-auto min-h-0"
                            class:active={currentTheme === theme}
                            data-set-theme={theme}
                            onclick={() => applyTheme(theme)}
                    >
                        <span class="capitalize text-xs">{theme}</span>
                        <span class="text-xs">{getThemeEmoji(theme)}</span>
                    </button>
                </li>
            {/each}
        </div>
    </ul>
</div>