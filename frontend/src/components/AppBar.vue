<script setup>
import {useRoute} from "vue-router";
import {ref} from "vue";
import {useAuthStore} from "@/stores/auth";
import router from "@/router";

const isAuthenticated = ref(false);

const authStore = useAuthStore();

const guestItems = [
  {
    id: 'home',
    text: 'Početna',
    icon: 'mdi-home',
    to: '/',
    color: 'primary',
  },
  {
    id: 'offers',
    text: 'Ponude',
    icon: 'mdi-basket',
    to: '/offers',
    color: 'primary',
  },
  {
    id: 'about',
    text: 'O nama',
    icon: 'mdi-information',
    to: '/about',
    color: 'primary',
  },
  {
    id: 'login',
    text: 'Prijava',
    icon: 'mdi-login',
    to: '/login',
    color: 'white',
  },
]

const userItems = [
  {
    id: 'home',
    text: 'Početna',
    icon: 'mdi-home',
    to: '/',
    color: 'primary',
  },
  {
    id: 'offers',
    text: 'Ponude',
    icon: 'mdi-basket',
    to: '/offers',
    color: 'primary',
  },
  {
    id: 'messages',
    text: 'Obavjesti',
    icon: 'mdi-message-text',
    to: '/messages',
    color: 'primary',
  },
  {
    id: 'account',
    text: 'Račun',
    icon: 'mdi-account',
    to: '/account',
    color: 'primary',
  },
]

const route = useRoute();

const hiddenRoutes = ['/login', '/register', '/order'];
const shouldHideNavBar = computed(() => hiddenRoutes.includes(route.path));

const logout = async () => {
  try {
    await authStore.logout();
    await router.push('/');
    window.location.reload();
  } catch (error) {
    throw error;
  }
}

onMounted(() => {
  isAuthenticated.value = authStore.auth.isAuthenticated;
})
</script>

<template>
  <v-app-bar v-if="$vuetify.display.mdAndUp" class="px-md-4 bg-primary" density="default" elevation="0">
    <RouterLink to="/" class="text-decoration-none d-flex flex-fill align-center logo-opacity">
      <v-img
        class="me-sm-8 mx-4"
        max-width="50"
        src="/logo.png"
      />
      <v-app-bar-title class="text-white text-h4 font-weight-medium">
        Gastrozoom
      </v-app-bar-title>
    </RouterLink>

    <v-spacer/>

    <div v-for="button in (isAuthenticated ? userItems : guestItems)">
      <v-btn
        :key="button.id"
        :color="button.color"
        class="mr-2 text-none"
        :class="button.color === 'white' ? 'text-primary' : 'text-white'"
        variant="flat"
        rounded="lg"
        :to="button.to"
        :prepend-icon="button.icon"
      >
        <span>{{ button.text }}</span>
      </v-btn>
      <v-btn v-if="button.id === 'account'" icon="mdi-cart" variant="plain" class="ml-2 mr-4 custom-radius" to="/order"/>
    </div>

    <v-btn v-if="isAuthenticated" @click="logout" color="secondary" class="me-2 text-none" variant="outlined" rounded="lg">
      <v-icon>mdi-logout</v-icon>
      <span>Odjava</span>
    </v-btn>
  </v-app-bar>


  <v-bottom-navigation v-if="$vuetify.display.smAndDown && !shouldHideNavBar" bg-color="transparent" elevation="0" mode="shift"
                       class="w-100 h-auto pb-5 pb-sm-6 pb-md-8 pt-12 position-fixed">
    <v-row justify="center">
      <v-col cols="11" class="pa-2 pa-sm-4 w-auto bg-white custom-shadow custom-radius d-flex justify-center">
        <v-btn
          v-for="button in (isAuthenticated ? userItems : guestItems)"
          :key="button.id"
          :to="button.to"
          :size="$vuetify.display.smAndUp ? 'small' : 'x-small'"
          rounded="lg"
          color="primary"
          class="text-primary mx-0 mx-sm-1"
        >
          <v-icon>{{ button.icon }}</v-icon>
          <span>{{ button.text }}</span>
        </v-btn>
      </v-col>
    </v-row>
  </v-bottom-navigation>
</template>

<style scoped>
.logo-opacity {
  transition: transform 0.3s ease, opacity 0.3s ease;
  transform-origin: center;
}

.logo-opacity:hover {
  opacity: 70%;
}

.custom-radius {
  border-radius: 24px;
}

.custom-shadow {
  box-shadow: 0 0 32px 8px #ECEFF1;
}
</style>
