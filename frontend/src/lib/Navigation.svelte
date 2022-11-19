<script lang="ts">
import TopAppBar, { Row, Section, Title } from '@smui/top-app-bar'
import IconButton from '@smui/icon-button'
import Menu from '@smui/menu'
import List, { Item, Separator, Text } from '@smui/list'
import {darkMode} from '../stores.js'

let topBarMenu: Menu;

function toggleTheme() {
    darkMode.update(n => !n)
}
</script>

<TopAppBar variant="static">
    <Row>
        <Section>
        <Title>pylon</Title>
        </Section>
        <div>
        <Section align="end" toolbar>
        <IconButton on:click={() => topBarMenu.setOpen(true)} class="material-icons" aria-label="Person">person</IconButton>
        <Menu bind:this={topBarMenu} anchorCorner="BOTTOM_LEFT">
            <List>
                <Item on:SMUI:action={toggleTheme}>
                    <Text>Dark Mode</Text>
                </Item>
            </List>
        </Menu>
        </Section>
        </div>
    </Row>
</TopAppBar>

<svelte:head>
  {#if $darkMode}
    <link rel="stylesheet" href="/smui-dark.css" />
  {:else}
    <link rel="stylesheet" href="/smui.css" />
  {/if}
</svelte:head>