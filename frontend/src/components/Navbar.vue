<template>
  <div>
    <v-app-bar
      app
      color="primary"
    >
      <v-toolbar-title>pylon</v-toolbar-title>
      <v-spacer></v-spacer>
      <v-menu open-on-hover offset-y>
        <template v-slot:activator="{ on }">
          <v-btn large outlined v-on="on">
            <v-icon>mdi-account</v-icon>
          </v-btn>
        </template>
        <v-list style="overflow: hidden;">
          <v-list-item>
            <v-list-item-icon>
              <v-icon>mdi-logout</v-icon>
            </v-list-item-icon>
            <v-list-item-title class="text-center">Logout</v-list-item-title>
          </v-list-item>
          <v-list-item>
            <v-switch
              class="mt-0 pt-0"
              v-model="$vuetify.theme.dark"
              hide-details
            ></v-switch>
            <v-list-item-title class="text-center">Dark</v-list-item-title>
          </v-list-item>
        </v-list>
      </v-menu>
    </v-app-bar>
  </div>
</template>

<script>
  export default {
  }
</script>

<style>
  .theme--dark.v-btn--active:before, .theme--dark.v-btn:focus:before {
    opacity: 0;
  }
  .v-app-bar>.v-toolbar__content {
    height: inherit !important;
    padding-top: 0 !important;
    padding-bottom: 0 !important;
  }
</style>