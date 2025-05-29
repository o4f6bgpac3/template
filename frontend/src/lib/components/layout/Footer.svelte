<script lang="ts">
    import {buildInfo} from '$lib/build-info';

    const buildDate = new Date(buildInfo.buildTime).toISOString();
</script>

<footer class="footer footer-center p-4 bg-base-200 text-base-content">
    <div class="flex flex-col sm:flex-row items-center gap-4 text-sm">
        <p>Built at {buildDate}</p>
    </div>
</footer>