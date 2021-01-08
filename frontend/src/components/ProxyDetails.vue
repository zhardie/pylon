<template>
  <v-row justify="center">
    <v-dialog :value="dialog" persistent max-width="600px">
      <v-card>
        <v-card-title>
          <span class="title mx-auto">{{ dialog.external }} <v-icon>mdi-chevron-right</v-icon> {{ dialog.internal }}</span>
        </v-card-title>
        <v-card-text>
          <v-container>
            <v-row>
              <v-col cols="12">
                <span class="subtitle-1">Authorized Users</span>
              </v-col>
              <v-col cols="12">
                <v-simple-table>
                  <thead>
                    <tr>
                      <th class="text-left">email</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="email in proxy_details.allowed_users" v-bind:key="email.id">
                      <td>{{ email }}</td>
                      <td><v-btn icon @click="removeUser(email)"><v-icon>mdi-delete</v-icon></v-btn></td>
                    </tr>
                    <tr>
                      <td class="py-3">
                        <v-text-field ref="new_user_input" hide-details outlined dense v-model="new_user">
                        </v-text-field>
                      </td>
                      <td>
                        <v-btn icon @click="addUser"><v-icon>mdi-plus-circle</v-icon></v-btn>
                      </td>
                    </tr>
                  </tbody>
                </v-simple-table>
              </v-col>
              
            </v-row>
          </v-container>
        </v-card-text>
        <v-card-actions>
          <v-spacer></v-spacer>
          <v-btn color="blue darken-1" text @click="$emit('closedModal')">Close</v-btn>
          <v-btn color="blue darken-1" text @click="$emit('saveConfig')">Save</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-row>
</template>

<script>
  export default {
    data: () => ({
      new_user: null
    }),
    methods: {
      removeUser(email) {
        this.proxy_details.allowed_users.splice( this.proxy_details.allowed_users.indexOf(email), 1 )
      },
      addUser() {
        this.proxy_details.allowed_users.push(this.new_user)
        this.new_user = null
      }
    },
    props: ['proxy_details'],
    computed: {
      dialog () {
        return this.proxy_details
      }
    }
  }
</script>