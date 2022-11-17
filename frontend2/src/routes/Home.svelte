<script lang="ts">
import { onMount } from 'svelte'
import IconButton from '@smui/icon-button'
import Textfield from '@smui/textfield'
import DataTable, { Head, Body, Row, Cell } from '@smui/data-table'
import ProxyDetail from '../lib/ProxyDetail.svelte'
import Snackbar, { Actions, Label } from '@smui/snackbar'
import Button from '@smui/button'
import LayoutGrid, { Cell as GridCell } from '@smui/layout-grid'

let config
let proxyDetail
let configSnackbar: Snackbar;

onMount(async () => {
    // Dev
    if (import.meta.env.DEV) {
        config = {
    "tldn": "bar.com",
    "allowed_users": null,
    "proxies": [
        {
            "internal": "http://192.168.1.1:1001",
            "external": "foo.bar.com",
            "allowed_users": [
                "foo@bar.com"
            ],
            "unauthenticated_routes": []
        },
        {
            "internal": "http://192.168.1.2:2002",
            "external": "foo2.bar.com",
            "allowed_users": [
                "foo@bar.com"
            ],
            "unauthenticated_routes": []
        }]}
    } else {
        // Prod
		const res = await fetch(`/config`)
		config = await res.json()
    }
    })

function deleteProxy(index) {
    config.proxies.splice(index, 1)
    if (config.proxies.length <= 0) {
        addProxy({internal: null, external: null, allowed_users: [], unauthenticated_routes: []})
    }
    config = config
}

function addProxy(proxy) {
    config.proxies = [...config.proxies, proxy]
}

async function saveConfig() {
    // Dev
    if (import.meta.env.DEV) {
        configSnackbar.open()
    } else {
        //Prod
        const res = await fetch('/config', {
            method: 'POST',
            body: JSON.stringify(config)
        })

        console.log(res.json())
        configSnackbar.open()
    }
}
</script>

<div>
<LayoutGrid>
<GridCell span={1} />
<GridCell class="center_cell" span={10}>
{#if config}
    <DataTable table$aria-label="Proxy list" style="width: 100%;">
        <Head>
            <Row>
            <Cell>External</Cell>
            <Cell>Internal</Cell>
            <Cell></Cell>
            <Cell></Cell>
            </Row>
        </Head>
        <Body>
            {#each config.proxies as proxy, i}
            <Row class="proxy_row">
                <Cell>
                    <Textfield class="proxy_entry" variant="outlined" bind:value={proxy.external} />
                </Cell>
                <Cell>
                    <Textfield class="proxy_entry" variant="outlined" bind:value={proxy.internal} />
                </Cell>
                <Cell><IconButton class="material-icons" aria-label="Info" on:click={() => (proxyDetail = proxy)}>info</IconButton></Cell>
                <Cell><IconButton class="material-icons" aria-label="Delete" on:click={() => (deleteProxy(i))}>delete</IconButton></Cell>
            </Row>
            {/each}
            <Row>
                <Cell>
                    <Button on:click={saveConfig}>
                        <Label>Save Config</Label>
                    </Button>
                    <Snackbar bind:this={configSnackbar}>
                        <Label>Saved Configuration</Label>
                        <Actions>
                        <IconButton class="material-icons" title="Dismiss">close</IconButton>
                        </Actions>
                    </Snackbar>
                </Cell>
                <Cell></Cell>
                <Cell></Cell>
                <Cell><IconButton class="material-icons" aria-label="Add" on:click={() => {addProxy({internal: null, external: null, allowed_users: [], unauthenticated_routes: []})}}>add</IconButton></Cell>
            </Row>
        </Body>
    </DataTable>
    <ProxyDetail bind:config bind:proxyDetail />
{/if}
</GridCell>
<GridCell span={1} />
</LayoutGrid>
</div>


<div>
    <LayoutGrid>
    <GridCell class="center_cell" span={10}>
        <div class="mdc-typography--overline">{JSON.stringify(config)}</div>
    </GridCell>
    </LayoutGrid>
</div>



<style>
    * :global(.proxy_entry) {
        width: 100%;
        margin-bottom: .5rem;
        margin-top: .5rem;
    }

    * :global(.center_cell) {
    /* height: 60px; */
    /* display: flex; */
    justify-content: center;
    align-items: center;
    /* margin-left: auto;
    margin-right: auto; */
    /* margin-left: 10%;
    margin-right: 10%; */
    background-color: orange;
    /* background-color: var(--mdc-theme-secondary, #333);
    color: var(--mdc-theme-on-secondary, #fff); */
  }

  .demo-cell {
    height: 60px;
    display: flex;
    justify-content: center;
    align-items: center;
    background-color: var(--mdc-theme-secondary, #333);
    color: var(--mdc-theme-on-secondary, #fff);
  }
</style>