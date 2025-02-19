<script setup>

import AccountMenuCard from "@/components/AccountMenuCard.vue";
import {useAuthStore} from "@/stores/auth";
import router from "@/router";

const authStore = useAuthStore();

onMounted(async () => {
  await authStore.getProfile();
});

const menuItems = [
  {
    title: 'Moje narudžbe',
    prependIcon: 'mdi-cart',
    link: '/orders'
  },
  {
    title: 'Adrese',
    prependIcon: 'mdi-map-marker',
    link: '/address'
  },
  {
    title: 'O nama',
    prependIcon: 'mdi-information',
    link: '/about'
  },
];

const adminMenuItems = [
  {
    title: 'Upravljanje ponudama',
    prependIcon: 'mdi-store-edit',
    link: '/admin/offers'
  },
  {
    title: 'Kreiraj obavjest',
    prependIcon: 'mdi-message-plus',
    link: '/admin/message/create'
  },
];

const workerMenuItems = [
  {
    title: 'Upravljanje narudžbama',
    prependIcon: 'mdi-cart-arrow-down',
    link: '/worker/orders'
  },
];

const logout = async () => {
  try {
    await authStore.logout();
    await router.push('/');
    window.location.reload();
  } catch (error) {
    throw error;
  }
}

onMounted(async () => {
  if (!authStore.auth.isAuthenticated) await router.push('/login');
})
</script>

<template>
  <v-container fluid>
    <v-row class="pt-4 pb-16">
      <v-col cols="12" sm="10" md="8" lg="6" offset-sm="1" offset-md="2" offset-lg="3" class="d-flex py-4">
        <v-icon size="6rem">mdi-account-circle</v-icon>
        <div class="d-flex flex-column pa-4 responsive-text">
          <h4 class="text-h6 text-sm-h5 text-md-h4 font-weight-medium text-truncate">{{ authStore.user.name }}</h4>
          <span class="text-caption text-sm-subtitle-2 text-md-subtitle-1 text-medium-emphasis text-truncate">
            {{ authStore.user.email }}
          </span>
        </div>
      </v-col>
      <v-col v-if="authStore.auth.role === 'ADMIN'" v-for="item in workerMenuItems" cols="12" sm="10" md="8" lg="6"
             offset-sm="1" offset-md="2" offset-lg="3"
      >
        <AccountMenuCard :link="item.link" :prepend-icon="item.prependIcon" :title="item.title"/>
      </v-col>
      <v-col v-if="authStore.auth.role === 'WORKER' || authStore.auth.role === 'ADMIN'" v-for="item in adminMenuItems" cols="12" sm="10" md="8"
             lg="6" offset-sm="1" offset-md="2" offset-lg="3"
      >
        <AccountMenuCard :link="item.link" :prepend-icon="item.prependIcon" :title="item.title"/>
      </v-col>
      <v-col v-for="item in menuItems" cols="12" sm="10" md="8" lg="6" offset-sm="1" offset-md="2" offset-lg="3">
        <AccountMenuCard :link="item.link" :prepend-icon="item.prependIcon" :title="item.title"/>
      </v-col>
      <v-col cols="12" sm="10" md="8" lg="6" offset-sm="1" offset-md="2" offset-lg="3">
        <AccountMenuCard @click="logout" prepend-icon="mdi-logout" title="Odjavi se"/>
      </v-col>
    </v-row>
  </v-container>
</template>

<style scoped>
.responsive-text {
  width: 100%;
}

@media (min-width: 150px) {
  .responsive-text {
    width: 60%;
  }
}

@media (min-width: 300px) {
  .responsive-text {
    width: 65%;
  }
}

@media (min-width: 325px) {
  .responsive-text {
    width: 75%;
  }
}

@media (min-width: 500px) {
  .responsive-text {
    width: 80%;
  }
}

@media (min-width: 680px) {
  .responsive-text {
    width: 82%;
  }
}



@media (min-width: 860px) {
  .responsive-text {
    width: 85%;
  }
}
</style>
